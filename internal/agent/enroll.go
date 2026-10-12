package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"proxbackup/internal/api"
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
		return &statusError{Code: resp.StatusCode, Msg: fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(body)))}
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// statusError is a non-2xx reply from the server.
type statusError struct {
	Code int
	Msg  string
}

func (e *statusError) Error() string { return e.Msg }

// permanent reports whether retrying the request cannot succeed (4xx other than 408/429).
func permanent(err error) bool {
	se, ok := err.(*statusError)
	return ok && se.Code >= 400 && se.Code < 500 && se.Code != 408 && se.Code != 429
}
