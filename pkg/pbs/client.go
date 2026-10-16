// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	protocolBackupV1 = "proxmox-backup-protocol-v1"
	protocolReaderV1 = "proxmox-backup-reader-protocol-v1"
	userAgent        = "proxbackup/0.1 (proxmox-backup-client compatible)"
	defaultPort      = "8007"
)

// Config describes how to reach and authenticate against a PBS instance.
type Config struct {
	// Host is "host" or "host:port" (default port 8007).
	Host string
	// Fingerprint is the SHA-256 fingerprint of the server certificate
	// ("aa:bb:..." or plain hex). When empty the system roots are used.
	Fingerprint string
	// AuthID is the API token id, e.g. "backup@pbs!pc-01".
	AuthID string
	// Secret is the API token secret (UUID).
	Secret string
}

// Client talks to a single PBS server.
type Client struct {
	cfg  Config
	addr string
	http *http.Client
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Host == "" || cfg.AuthID == "" || cfg.Secret == "" {
		return nil, errors.New("pbs: host, auth id and secret are required")
	}
	if !strings.Contains(cfg.AuthID, "!") {
		return nil, errors.New("pbs: auth id must be an API token id (user@realm!name)")
	}
	addr := cfg.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, defaultPort)
	}
	c := &Client{cfg: cfg, addr: addr}
	c.http = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     c.tlsConfig(),
			TLSHandshakeTimeout: 15 * time.Second,
			ForceAttemptHTTP2:   false,
		},
	}
	return c, nil
}

// NormalizeFingerprint lowercases a fingerprint and strips separators.
func NormalizeFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(fp))
}

// FormatFingerprint renders a certificate fingerprint the way PBS displays it.
func FormatFingerprint(sum [32]byte) string {
	h := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func (c *Client) tlsConfig() *tls.Config {
	host, _, _ := net.SplitHostPort(c.addr)
	if c.cfg.Fingerprint == "" {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	want := NormalizeFingerprint(c.cfg.Fingerprint)
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by fingerprint pinning below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("pbs: server sent no certificate")
			}
			got := sha256.Sum256(raw[0])
			if hex.EncodeToString(got[:]) != want {
				return fmt.Errorf("pbs: certificate fingerprint mismatch (got %s)", FormatFingerprint(got))
			}
			return nil
		},
	}
}

func (c *Client) authHeader() string {
	return "PBSAPIToken " + c.cfg.AuthID + ":" + url.PathEscape(c.cfg.Secret)
}

// APIError is returned for non-2xx responses.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pbs: HTTP %d: %s", e.Status, strings.TrimSpace(e.Message))
}

// IsNotFound reports whether err is a 404, or one of the 400s PBS uses for
// missing things ("no valid previous backup", "snapshot ... does not exist!").
func IsNotFound(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == http.StatusNotFound ||
		(ae.Status == http.StatusBadRequest &&
			(strings.Contains(ae.Message, "no valid previous backup") || strings.Contains(ae.Message, "does not exist")))
}

func decodeAPIResponse(resp *http.Response, out any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(body)
		if msg == "" {
			msg = resp.Status
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("pbs: bad JSON response: %w", err)
	}
	if len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// Call performs a regular (HTTP/1.1) REST API call under /api2/json.
// For GET and DELETE, params are encoded in the query string; otherwise as JSON body.
func (c *Client) Call(ctx context.Context, method, path string, params map[string]any, out any) error {
	u := "https://" + c.addr + "/api2/json/" + strings.TrimPrefix(path, "/")
	var body io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		if q := encodeQuery(params); q != "" {
			u += "?" + q
		}
	} else if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return decodeAPIResponse(resp, out)
}

// Download performs a GET of path (relative to /api2/json, may contain a query)
// and streams the raw response body to w. Used for non-JSON endpoints such as
// pxar-file-download.
func (c *Client) Download(ctx context.Context, path string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.addr+"/api2/json/"+strings.TrimPrefix(path, "/"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return decodeAPIResponse(resp, nil)
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return err
}

func encodeQuery(params map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	v := url.Values{}
	for k, val := range params {
		switch x := val.(type) {
		case nil:
		case []string:
			for _, s := range x {
				v.Add(k, s)
			}
		default:
			v.Set(k, fmt.Sprint(x))
		}
	}
	return v.Encode()
}

// h2Session is an HTTP/2 connection obtained via the PBS protocol upgrade.
type h2Session struct {
	conn net.Conn
	cc   *http2.ClientConn
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// upgrade performs the HTTP/1.1 -> PBS protocol upgrade and starts HTTP/2 on the
// same TLS stream, as pbs-client's start_h2_connection does.
func (c *Client) upgrade(ctx context.Context, path string, params map[string]any, protocol string) (*h2Session, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}, Config: c.tlsConfig()}
	raw, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("pbs: connect %s: %w", c.addr, err)
	}
	conn := raw.(*tls.Conn)
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(60 * time.Second))
	}

	target := "/api2/json/" + path
	if q := encodeQuery(params); q != "" {
		target += "?" + q
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: %s\r\nConnection: upgrade\r\nUpgrade: %s\r\n\r\n",
		target, c.addr, userAgent, c.authHeader(), protocol)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pbs: upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		err := decodeAPIResponse(resp, nil)
		conn.Close()
		if err == nil {
			err = fmt.Errorf("pbs: upgrade failed: %s", resp.Status)
		}
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	t := &http2.Transport{
		MaxReadFrameSize: 4 << 20,
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
	}
	cc, err := t.NewClientConn(&bufferedConn{Conn: conn, r: br})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pbs: http2 handshake: %w", err)
	}
	return &h2Session{conn: conn, cc: cc}, nil
}

func (s *h2Session) newRequest(ctx context.Context, method, path string, params map[string]any, body []byte, contentType string) (*http.Request, error) {
	u := "https://localhost/" + strings.TrimPrefix(path, "/")
	if q := encodeQuery(params); q != "" {
		if len(q) > 4096 {
			return nil, errors.New("pbs: h2 query too long")
		}
		u += "?" + q
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

// call sends one request on the h2 session and decodes the {"data":...} reply.
func (s *h2Session) call(ctx context.Context, method, path string, params map[string]any, body []byte, contentType string, out any) error {
	req, err := s.newRequest(ctx, method, path, params, body, contentType)
	if err != nil {
		return err
	}
	resp, err := s.cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("pbs: %s %s: %w", method, path, err)
	}
	return decodeAPIResponse(resp, out)
}

// download streams a raw response body (index files, blobs, chunks) into memory.
func (s *h2Session) download(ctx context.Context, path string, params map[string]any) ([]byte, error) {
	req, err := s.newRequest(ctx, http.MethodGet, path, params, nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := s.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("pbs: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, decodeAPIResponse(resp, nil)
	}
	return io.ReadAll(resp.Body)
}

func (s *h2Session) Close() error {
	s.cc.Close()
	return s.conn.Close()
}
