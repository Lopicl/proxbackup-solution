package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"pbspc/internal/api"
)

// NotifySettings are stored in the settings table under "notifications".
type NotifySettings struct {
	WebhookURL  string `json:"webhook_url"`
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	SMTPUser    string `json:"smtp_user"`
	SMTPPassEnc []byte `json:"smtp_pass_enc,omitempty"`
	SMTPFrom    string `json:"smtp_from"`
	SMTPTo      string `json:"smtp_to"`  // comma separated
	SMTPTLS     string `json:"smtp_tls"` // "starttls" (default) | "tls" | "none"
	OnSuccess   bool   `json:"on_success"`
	OnFailure   bool   `json:"on_failure"`
	StaleDays   int    `json:"stale_days"` // alert when a client has no successful backup for N days (0 = off)
}

type notifyView struct {
	NotifySettings
	SMTPPassword string `json:"smtp_password,omitempty"` // write-only
	SMTPPassSet  bool   `json:"smtp_password_set"`
}

// Notifier sends webhook and email notifications.
type Notifier struct{ s *Server }

func (n *Notifier) settings(ctx context.Context) NotifySettings {
	ns := NotifySettings{OnFailure: true, SMTPPort: 587, SMTPTLS: "starttls", StaleDays: 3}
	n.s.store.Setting(ctx, "notifications", &ns)
	return ns
}

// Message is the payload sent to webhooks.
type Message struct {
	Event    string `json:"event"` // "run.finished" | "client.stale" | "test"
	Severity string `json:"severity"`
	Subject  string `json:"subject"`
	Text     string `json:"text"`
	Run      *Run   `json:"run,omitempty"`
	Client   string `json:"client,omitempty"`
}

func (n *Notifier) RunFinished(ctx context.Context, r *Run) {
	ns := n.settings(ctx)
	failed := r.State == api.RunFailed || r.State == api.RunLost
	if (failed && !ns.OnFailure) || (!failed && !ns.OnSuccess) || r.State == api.RunCanceled {
		return
	}
	sev := "info"
	if failed {
		sev = "error"
	} else if r.State == api.RunWarning {
		sev = "warning"
	}
	what := r.JobName
	if what == "" {
		what = r.Kind
	}
	subj := fmt.Sprintf("[pbspc] %s: %s on %s", strings.ToUpper(r.State), what, r.ClientName)
	var b strings.Builder
	fmt.Fprintf(&b, "Client:   %s\nJob:      %s (%s)\nState:    %s\n", r.ClientName, what, r.Kind, r.State)
	if r.Snapshot != "" {
		fmt.Fprintf(&b, "Snapshot: %s\n", r.Snapshot)
	}
	if r.StartedAt > 0 && r.FinishedAt >= r.StartedAt {
		fmt.Fprintf(&b, "Duration: %s\n", time.Duration(r.FinishedAt-r.StartedAt)*time.Second)
	}
	fmt.Fprintf(&b, "Data:     %s total, %s uploaded, %d files, %d skipped\n",
		humanBytes(r.Result.BytesTotal), humanBytes(r.Result.BytesUploaded), r.Result.Files, r.Result.Skipped)
	if r.Error != "" {
		fmt.Fprintf(&b, "\nError: %s\n", r.Error)
	}
	n.send(ctx, ns, Message{Event: "run.finished", Severity: sev, Subject: subj, Text: b.String(), Run: r, Client: r.ClientName})
}

// CheckStale alerts about clients without a recent successful backup.
func (n *Notifier) CheckStale(ctx context.Context) {
	ns := n.settings(ctx)
	if ns.StaleDays <= 0 {
		return
	}
	clients, err := n.s.store.Clients(ctx)
	if err != nil {
		return
	}
	last := n.s.store.LastSuccess(ctx)
	limit := time.Duration(ns.StaleDays) * 24 * time.Hour
	for _, c := range clients {
		t := last[c.ID]
		if t == 0 && time.Since(time.Unix(c.CreatedAt, 0)) < limit {
			continue
		}
		if t == 0 || time.Since(time.Unix(t, 0)) > limit {
			when := "never"
			if t > 0 {
				when = time.Unix(t, 0).Format(time.RFC1123)
			}
			n.send(ctx, ns, Message{Event: "client.stale", Severity: "warning", Client: c.Name,
				Subject: fmt.Sprintf("[pbspc] %s has no backup for %d days", c.Name, ns.StaleDays),
				Text:    fmt.Sprintf("Client %s: last successful backup %s. Last seen %s.\n", c.Name, when, time.Unix(c.LastSeen, 0).Format(time.RFC1123))})
		}
	}
}

func (n *Notifier) send(ctx context.Context, ns NotifySettings, m Message) []error {
	var errs []error
	if ns.WebhookURL != "" {
		if err := postWebhook(ctx, ns.WebhookURL, m); err != nil {
			n.s.log.Warn("webhook failed", "err", err)
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	if ns.SMTPHost != "" && ns.SMTPTo != "" {
		pass, _ := n.s.sealer.Open(ns.SMTPPassEnc)
		if len(ns.SMTPPassEnc) == 0 {
			pass = ""
		}
		if err := sendMail(ns, pass, m.Subject, m.Text); err != nil {
			n.s.log.Warn("email failed", "err", err)
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}
	return errs
}

func postWebhook(ctx context.Context, url string, m Message) error {
	b, _ := json.Marshal(m)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(resp.Status)
	}
	return nil
}

func sendMail(ns NotifySettings, pass, subject, body string) error {
	addr := net.JoinHostPort(ns.SMTPHost, strconv.Itoa(ns.SMTPPort))
	var to []string
	for _, t := range strings.Split(ns.SMTPTo, ",") {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		ns.SMTPFrom, strings.Join(to, ", "), subject, time.Now().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))

	var conn net.Conn
	var err error
	d := &net.Dialer{Timeout: 15 * time.Second}
	if ns.SMTPTLS == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: ns.SMTPHost})
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, ns.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ns.SMTPTLS == "starttls" || ns.SMTPTLS == "" {
		if err := c.StartTLS(&tls.Config{ServerName: ns.SMTPHost}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if ns.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", ns.SMTPUser, pass, ns.SMTPHost)); err != nil {
			return err
		}
	}
	if err := c.Mail(ns.SMTPFrom); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (s *Server) handleGetNotify(w http.ResponseWriter, r *http.Request) {
	ns := s.notify.settings(r.Context())
	v := notifyView{NotifySettings: ns, SMTPPassSet: len(ns.SMTPPassEnc) > 0}
	v.SMTPPassEnc = nil
	writeJSON(w, v)
}

func (s *Server) handleSaveNotify(w http.ResponseWriter, r *http.Request) {
	var v notifyView
	if err := decodeJSON(r, &v); err != nil {
		httpError(w, 400, err)
		return
	}
	old := s.notify.settings(r.Context())
	ns := v.NotifySettings
	ns.SMTPPassEnc = old.SMTPPassEnc
	if v.SMTPPassword != "" {
		ns.SMTPPassEnc = s.sealer.Seal(v.SMTPPassword)
	}
	if ns.SMTPPort == 0 {
		ns.SMTPPort = 587
	}
	if err := s.store.SetSetting(r.Context(), "notifications", ns); err != nil {
		httpError(w, 500, err)
		return
	}
	s.handleGetNotify(w, r)
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	ns := s.notify.settings(r.Context())
	if ns.WebhookURL == "" && ns.SMTPHost == "" {
		httpError(w, 400, errors.New("no webhook or SMTP server configured"))
		return
	}
	errs := s.notify.send(r.Context(), ns, Message{Event: "test", Severity: "info", Subject: "[pbspc] test notification",
		Text: "This is a test notification from pbspc-server.\n"})
	if len(errs) > 0 {
		httpError(w, 502, errors.Join(errs...))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
