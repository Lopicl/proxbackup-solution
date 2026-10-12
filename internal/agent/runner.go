package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"pbspc/internal/api"
)

// Enroll exchanges a one-time enrollment token for a client certificate and
// writes the agent configuration to dir.
func Enroll(ctx context.Context, dir, token string) (*Config, error) {
	t, err := ParseEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := newKeyAndCSR(hostname)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: pinnedCAConfig(t.CAFingerprint)}}
	req := api.EnrollRequest{Code: t.Code, CSR: string(csrPEM), Hostname: hostname, OS: osDescription()}
	var resp api.EnrollResponse
	if err := postJSON(ctx, hc, strings.TrimRight(t.URL, "/")+"/agent/v1/enroll", req, &resp); err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	c := &Config{ServerURL: strings.TrimRight(t.URL, "/"), ClientID: resp.ClientID, ClientName: resp.ClientName, dir: dir}
	for name, data := range map[string][]byte{"client.key": keyPEM, "client.pem": []byte(resp.CertPEM), "ca.pem": []byte(resp.CAPEM)} {
		if err := writeSecret(c.path(name), data); err != nil {
			return nil, err
		}
	}
	return c, c.save()
}

func osDescription() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func postJSON(ctx context.Context, hc *http.Client, url string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// Runner polls the management server and executes jobs one at a time.
type Runner struct {
	cfg     *Config
	hc      *http.Client
	version string
	log     *slog.Logger

	mu      sync.Mutex
	running map[int64]context.CancelFunc
	queue   chan api.JobSpec
}

// NewRunner creates a runner from an enrolled configuration.
func NewRunner(cfg *Config, version string, log *slog.Logger) (*Runner, error) {
	tc, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	return &Runner{
		cfg:     cfg,
		hc:      &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, IdleConnTimeout: 2 * time.Minute}},
		version: version,
		log:     log,
		running: map[int64]context.CancelFunc{},
		queue:   make(chan api.JobSpec, 32),
	}, nil
}

// Run blocks until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	go r.worker(ctx)
	backoff := time.Second
	hostname, _ := os.Hostname()
	for ctx.Err() == nil {
		req := api.PollRequest{Hostname: hostname, OS: osDescription(), AgentVersion: r.version, RunningRuns: r.runningIDs()}
		var resp api.PollResponse
		err := postJSON(ctx, r.hc, r.cfg.ServerURL+"/agent/v1/poll?wait=30", req, &resp)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			r.log.Warn("poll failed", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, id := range resp.Cancel {
			r.mu.Lock()
			if cancel := r.running[id]; cancel != nil {
				r.log.Info("canceling run", "run", id)
				cancel()
			}
			r.mu.Unlock()
		}
		for _, j := range resp.Jobs {
			r.log.Info("received job", "run", j.RunID, "kind", j.Kind)
			r.mu.Lock()
			r.running[j.RunID] = func() {} // placeholder until it starts
			r.mu.Unlock()
			r.queue <- j
		}
	}
	return ctx.Err()
}

func (r *Runner) runningIDs() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]int64, 0, len(r.running))
	for id := range r.running {
		ids = append(ids, id)
	}
	return ids
}

// worker executes queued jobs sequentially (VSS and disk I/O don't benefit from parallel runs).
func (r *Runner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case spec := <-r.queue:
			r.execute(ctx, spec)
		}
	}
}

func (r *Runner) execute(parent context.Context, spec api.JobSpec) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	r.mu.Lock()
	r.running[spec.RunID] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.running, spec.RunID)
		r.mu.Unlock()
	}()

	rep := newEventReporter(r, spec.RunID)
	rep.Log("info", fmt.Sprintf("starting %s job (agent %s)", spec.Kind, r.version))
	res := Run(ctx, spec, rep)
	r.log.Info("run finished", "run", spec.RunID, "state", res.State, "err", res.Error)
	rep.finish(parent, res)
}

// eventReporter batches events and delivers them to the server in order.
type eventReporter struct {
	r      *Runner
	runID  int64
	mu     sync.Mutex
	buf    []api.Event
	last   time.Time
	ch     chan []api.Event
	done   chan struct{}
	closed bool
}

func newEventReporter(r *Runner, runID int64) *eventReporter {
	e := &eventReporter{r: r, runID: runID, ch: make(chan []api.Event, 64), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		for batch := range e.ch {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			e.send(ctx, batch, 3)
			cancel()
		}
	}()
	return e
}

func (e *eventReporter) Log(level, msg string) {
	e.r.log.Info(msg, "run", e.runID, "level", level)
	e.add(api.Event{Time: time.Now(), Type: "log", Level: level, Message: msg})
}

func (e *eventReporter) Progress(p api.Progress) {
	e.add(api.Event{Time: time.Now(), Type: "progress", Progress: &p})
}

func (e *eventReporter) add(ev api.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.buf = append(e.buf, ev)
	if time.Since(e.last) > 2*time.Second || len(e.buf) > 200 {
		e.ch <- e.buf
		e.buf, e.last = nil, time.Now()
	}
}

func (e *eventReporter) send(ctx context.Context, batch []api.Event, attempts int) error {
	url := fmt.Sprintf("%s/agent/v1/runs/%d/events", e.r.cfg.ServerURL, e.runID)
	var err error
	for i := 0; i < attempts; i++ {
		if err = postJSON(ctx, e.r.hc, url, batch, nil); err == nil {
			return nil
		}
		select {
		case <-time.After(time.Duration(min(i+1, 15)) * 2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	e.r.log.Warn("could not deliver events", "run", e.runID, "err", err)
	return err
}

// finish delivers remaining events plus the result, retrying for a while
// because a lost result would leave the run hanging on the server.
func (e *eventReporter) finish(ctx context.Context, res api.Result) {
	e.mu.Lock()
	batch := append(e.buf, api.Event{Time: time.Now(), Type: "result", Result: &res})
	e.buf, e.closed = nil, true
	close(e.ch)
	e.mu.Unlock()
	<-e.done
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()
	e.send(ctx, batch, 60)
}
