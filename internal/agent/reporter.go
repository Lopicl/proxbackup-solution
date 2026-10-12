package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pbspc/internal/api"
)

// reporter delivers a run's events to the server in order. Runs the agent
// started itself carry a RunRegister and get their server id lazily, so a
// backup can start (and finish) while the server is unreachable. Whatever
// cannot be delivered is spooled to disk and sent later.
type reporter struct {
	r     *Runner
	reg   *api.RunRegister // nil for server-dispatched runs
	runID int64            // 0 until registered

	onRegistered func(runID int64)

	mu     sync.Mutex
	buf    []api.Event
	closed bool
	wake   chan struct{}
	done   chan struct{}
}

const maxBufferedEvents = 20000

func newReporter(r *Runner, reg *api.RunRegister, runID int64, onRegistered func(int64)) *reporter {
	e := &reporter{r: r, reg: reg, runID: runID, onRegistered: onRegistered, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go e.loop()
	return e
}

func (e *reporter) Log(level, msg string) {
	e.r.log.Info(msg, "run", e.label(), "level", level)
	e.add(api.Event{Time: time.Now(), Type: "log", Level: level, Message: msg})
}

func (e *reporter) Progress(p api.Progress) {
	e.add(api.Event{Time: time.Now(), Type: "progress", Progress: &p})
}

func (e *reporter) label() string {
	if e.runID > 0 {
		return fmt.Sprint(e.runID)
	}
	if e.reg != nil {
		return e.reg.UUID[:8]
	}
	return "?"
}

func (e *reporter) add(ev api.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	// Only the latest progress matters: replace a trailing progress event.
	if n := len(e.buf); ev.Type == "progress" && n > 0 && e.buf[n-1].Type == "progress" {
		e.buf[n-1] = ev
		return
	}
	if len(e.buf) >= maxBufferedEvents { // server unreachable for a long time: keep the newest
		e.buf = e.buf[1:]
	}
	e.buf = append(e.buf, ev)
}

func (e *reporter) loop() {
	defer close(e.done)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var closedAt time.Time
	for {
		select {
		case <-t.C:
		case <-e.wake:
		}
		err := e.flush()
		e.mu.Lock()
		closed, empty := e.closed, len(e.buf) == 0
		e.mu.Unlock()
		if closed {
			if closedAt.IsZero() {
				closedAt = time.Now()
			}
			// After the run: keep trying briefly, then hand over to the spool.
			if empty || (err != nil && time.Since(closedAt) > 30*time.Second) || (err != nil && permanent(err)) {
				return
			}
		}
	}
}

// flush registers the run if needed and sends buffered events.
func (e *reporter) flush() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if e.runID == 0 {
		id, err := e.r.register(ctx, e.reg)
		if err != nil {
			return err
		}
		e.runID = id
		if e.onRegistered != nil {
			e.onRegistered(id)
		}
	}
	e.mu.Lock()
	batch := append([]api.Event(nil), e.buf...)
	e.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if err := e.r.postEvents(ctx, e.runID, batch); err != nil {
		return err
	}
	e.mu.Lock()
	e.buf = e.buf[len(batch):]
	e.mu.Unlock()
	return nil
}

// finish queues the result and waits for delivery; undelivered events are spooled.
func (e *reporter) finish(res api.Result) {
	e.mu.Lock()
	e.buf = append(e.buf, api.Event{Time: time.Now(), Type: "result", Result: &res})
	e.closed = true
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	<-e.done
	e.mu.Lock()
	left := e.buf
	e.mu.Unlock()
	if len(left) > 0 {
		e.r.spool.put(spoolEntry{Reg: e.reg, RunID: e.runID, Events: left})
		e.r.log.Warn("server unreachable, run report spooled for later delivery", "run", e.label())
	}
}

// ---- spool ----

// spoolEntry is a run report waiting for the server.
type spoolEntry struct {
	Reg    *api.RunRegister `json:"reg,omitempty"`
	RunID  int64            `json:"run_id,omitempty"`
	Events []api.Event      `json:"events,omitempty"`
}

type spool struct {
	dir string
	mu  sync.Mutex
}

func (s *spool) put(e spoolEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	os.MkdirAll(s.dir, 0o700)
	name := fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), randomHex(4))
	b, _ := json.Marshal(e)
	writeSecret(filepath.Join(s.dir, name), b)
}

// drain delivers spooled reports in order; it stops at the first transient failure.
func (s *spool) drain(ctx context.Context, r *Runner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, _ := os.ReadDir(s.dir)
	for _, de := range entries {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		p := filepath.Join(s.dir, de.Name())
		b, err := os.ReadFile(p)
		var e spoolEntry
		if err != nil || json.Unmarshal(b, &e) != nil {
			os.Remove(p)
			continue
		}
		err = func() error {
			if e.RunID == 0 && e.Reg != nil {
				id, err := r.register(ctx, e.Reg)
				if err != nil {
					return err
				}
				e.RunID = id
			}
			if len(e.Events) > 0 && e.RunID > 0 {
				return r.postEvents(ctx, e.RunID, e.Events)
			}
			return nil
		}()
		switch {
		case err == nil:
			os.Remove(p)
			r.log.Info("delivered spooled run report", "run", e.RunID)
		case permanent(err):
			os.Remove(p)
			r.log.Warn("dropping spooled run report rejected by server", "err", err)
		default:
			// Persist a registration we got so the run isn't registered twice
			// with different ids (register is idempotent anyway).
			if e.RunID > 0 {
				b, _ := json.Marshal(e)
				writeSecret(p, b)
			}
			return
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
