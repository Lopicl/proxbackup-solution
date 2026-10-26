// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api defines the JSON contract between proxbackup-agent and proxbackup-server.
package api

import "time"

// Job kinds.
const (
	KindFiles   = "files"
	KindImage   = "image"
	KindRestore = "restore"
)

// Run states.
const (
	RunQueued     = "queued"
	RunDispatched = "dispatched"
	RunRunning    = "running"
	RunSuccess    = "success"
	RunWarning    = "warning" // finished, but some files were skipped
	RunFailed     = "failed"
	RunCanceled   = "canceled"
	RunLost       = "lost"   // agent stopped reporting
	RunMissed     = "missed" // scheduled run could not start in its window and catch-up is off
)

// Run triggers.
const (
	TriggerSchedule = "schedule" // started by the agent at the scheduled time
	TriggerCatchUp  = "catch-up" // started by the agent after a missed window (PC was off or busy)
	TriggerManual   = "manual"   // "Run now" / restore from the web UI
)

// Terminal reports whether a run state is final.
func Terminal(state string) bool {
	switch state {
	case RunSuccess, RunWarning, RunFailed, RunCanceled, RunLost, RunMissed:
		return true
	}
	return false
}

// PBSTarget is everything an agent needs to talk to PBS for one job.
type PBSTarget struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	Datastore   string `json:"datastore"`
	Namespace   string `json:"namespace"`
	AuthID      string `json:"auth_id"`
	Secret      string `json:"secret"`
}

// CryptKey is a client's encryption key, generated and escrowed by the server.
type CryptKey struct {
	Key         string `json:"key"`         // base64 of the 32 byte AES-256 key
	Fingerprint string `json:"fingerprint"` // PBS key fingerprint ("aa:bb:…")
	Created     int64  `json:"created"`     // unix seconds
	// MasterPubKey, if set, is a PEM RSA public key: each encrypted snapshot
	// also gets rsa-encrypted.key.blob, recoverable with the master private key.
	MasterPubKey string `json:"master_pubkey,omitempty"`
}

// RestoreSpec describes a restore job.
type RestoreSpec struct {
	BackupID   string   `json:"backup_id"`
	BackupTime int64    `json:"backup_time"`
	Archive    string   `json:"archive"`         // e.g. "c-users.pxar.didx"
	Paths      []string `json:"paths,omitempty"` // archive-relative paths; empty = everything
	TargetDir  string   `json:"target_dir"`      // where to restore to
	Overwrite  string   `json:"overwrite"`       // "skip" | "overwrite" | "if-newer"
	TargetDisk string   `json:"target_disk,omitempty"`
	// Namespace of the snapshot when it isn't the client's current one (it
	// was taken before the client moved to another namespace).
	Namespace string `json:"ns,omitempty"`
	// Session is set for restores a PC user started with "Restore files…"
	// in the tray app: the agent's reference to that user's restore session.
	// The agent checks the paths against the user's scope and, for users who
	// aren't administrators, writes the files as that user.
	Session string `json:"session,omitempty"`
	// RequestedBy is the Windows account of that user (for the run log).
	RequestedBy string `json:"requested_by,omitempty"`
}

// JobSpec is sent from server to agent to start a run.
type JobSpec struct {
	RunID    int64     `json:"run_id"`
	JobID    int64     `json:"job_id"`
	Kind     string    `json:"kind"`
	Target   PBSTarget `json:"target"`
	BackupID string    `json:"backup_id"`

	// files
	Sources  []string `json:"sources,omitempty"`  // absolute Windows paths, e.g. C:\Users
	Excludes []string `json:"excludes,omitempty"` // glob patterns
	UseVSS   bool     `json:"use_vss"`
	// ChangeDetection: "metadata" (pxar v2 split archives, unchanged files are
	// not read), "data" (split archives, every file read) or "legacy"/"" (one
	// pxar v1 archive, for PBS before 3.3).
	ChangeDetection string `json:"change_detection,omitempty"`
	// image
	Volumes []string `json:"volumes,omitempty"` // e.g. "C:"
	// restore
	Restore *RestoreSpec `json:"restore,omitempty"`
	// Encrypt backups client-side with Crypt. Crypt is also sent without
	// Encrypt, so encrypted snapshots can be restored and change detection
	// can read an encrypted previous snapshot.
	Encrypt bool      `json:"encrypt,omitempty"`
	Crypt   *CryptKey `json:"crypt,omitempty"`
	// PreventSleep keeps the PC awake while the run is going.
	PreventSleep bool `json:"prevent_sleep,omitempty"`
	// Bandwidth limits uploads to PBS: the job's own limit and the client's
	// (both apply; the lower rate wins).
	Bandwidth       Bandwidth `json:"bandwidth,omitzero"`
	ClientBandwidth Bandwidth `json:"client_bandwidth,omitzero"`
}

// JobConfig is a backup job as pushed to the agent. The agent owns the
// schedule: it decides when to start the job on its own clock.
type JobConfig struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	BackupID string   `json:"backup_id"`
	Sources  []string `json:"sources,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
	Volumes  []string `json:"volumes,omitempty"`
	UseVSS   bool     `json:"use_vss"`
	// ChangeDetection as in JobSpec.
	ChangeDetection string `json:"change_detection,omitempty"`
	// Schedule is a cron expression evaluated in the PC's local time zone; empty = manual only.
	Schedule string `json:"schedule"`
	// WindowMinutes: a scheduled run may start up to this long after its time.
	WindowMinutes int `json:"window_minutes"`
	// CatchUp: if the window was missed (PC off, asleep or busy), run as soon as possible
	// instead of recording the run as missed.
	CatchUp bool `json:"catch_up"`
	// Encrypt with the client key (AgentConfig.Crypt).
	Encrypt bool `json:"encrypt,omitempty"`
	// StartDelay (seconds) shifts every scheduled time of the job, spreading
	// the members of a group job so they don't all hit PBS at once.
	StartDelay int `json:"start_delay,omitempty"`
	// PreventSleep as in JobSpec.
	PreventSleep bool `json:"prevent_sleep,omitempty"`
	// WakeToRun wakes the PC from sleep or hibernation for scheduled runs.
	WakeToRun bool `json:"wake_to_run,omitempty"`
	// Bandwidth limits this job's uploads (see JobSpec).
	Bandwidth Bandwidth `json:"bandwidth,omitzero"`
}

// AgentConfig is everything the agent needs to run scheduled backups on its
// own, even while the management server is unreachable.
type AgentConfig struct {
	Rev    string      `json:"rev"` // content hash; the agent reports it back in PollRequest
	Target PBSTarget   `json:"target"`
	Jobs   []JobConfig `json:"jobs"`
	// Crypt is the client's encryption key, once one exists.
	Crypt *CryptKey `json:"crypt,omitempty"`
	// Bandwidth limits uploads of every job of the client.
	Bandwidth Bandwidth `json:"bandwidth,omitzero"`
}

// Spec turns a job config into an executable job spec.
func (c *AgentConfig) Spec(j JobConfig) JobSpec {
	return JobSpec{JobID: j.ID, Kind: j.Kind, Target: c.Target, BackupID: j.BackupID,
		Sources: j.Sources, Excludes: j.Excludes, Volumes: j.Volumes, UseVSS: j.UseVSS, ChangeDetection: j.ChangeDetection,
		Encrypt: j.Encrypt, Crypt: c.Crypt, PreventSleep: j.PreventSleep,
		Bandwidth: j.Bandwidth, ClientBandwidth: c.Bandwidth}
}

// JobState is the agent's view of a job's schedule, reported on every poll.
type JobState struct {
	JobID          int64 `json:"job_id"`
	NextRun        int64 `json:"next_run,omitempty"` // unix seconds, 0 = not scheduled
	LastSlot       int64 `json:"last_slot,omitempty"`
	CatchUpPending bool  `json:"catch_up_pending,omitempty"`
	Running        bool  `json:"running,omitempty"`
}

// PollRequest is the agent heartbeat.
type PollRequest struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	AgentVersion string     `json:"agent_version"`
	RunningRuns  []int64    `json:"running_runs"`
	ConfigRev    string     `json:"config_rev"`
	Schedule     []JobState `json:"schedule"`
	TimeZone     string     `json:"time_zone"`
	// PausedUntil (unix seconds, 0 = not paused): a PC user paused scheduled
	// backups from the tray app until then; PausedBy is their account.
	PausedUntil int64  `json:"paused_until,omitempty"`
	PausedBy    string `json:"paused_by,omitempty"`
	// TrayError: the service can't start the tray app in a user session
	// ("" = fine). See the agent log in %ProgramData%\proxbackup\logs.
	TrayError string `json:"tray_error,omitempty"`
}

// PollResponse carries config updates, on-demand work and cancellations.
type PollResponse struct {
	Config *AgentConfig `json:"config,omitempty"` // only sent when ConfigRev differs
	Jobs   []JobSpec    `json:"jobs"`             // manual runs and restores requested in the UI
	Cancel []int64      `json:"cancel"`
	// Update offers a newer agent; the agent installs it when idle.
	Update *AgentUpdate `json:"update,omitempty"`
	// ServerURL is the console's current agent-facing URL (PROXBACKUP_PUBLIC_URL).
	// Agents enrolled under another URL switch to it once it answers.
	ServerURL string `json:"server_url,omitempty"`
}

// AgentUpdate describes an agent binary the server offers.
type AgentUpdate struct {
	Version string `json:"version"`
	URL     string `json:"url"` // path on the server, e.g. /agent/v1/update/windows-amd64 (mTLS)
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	// Force is set when an admin pushed the update: install it even if an
	// earlier attempt failed within the hour.
	Force bool `json:"force,omitempty"`
}

// RunRegister announces a run the agent started on its own (scheduled or
// catch-up), or a scheduled run it had to skip. It is idempotent on UUID, so
// the agent can retry until the server is reachable.
type RunRegister struct {
	UUID         string `json:"uuid"`
	JobID        int64  `json:"job_id"`
	Kind         string `json:"kind"`
	Trigger      string `json:"trigger"`
	State        string `json:"state"` // "running" or "missed"
	ScheduledFor int64  `json:"scheduled_for"`
	StartedAt    int64  `json:"started_at"`
	Message      string `json:"message,omitempty"`
}

// RunRegisterResponse returns the server's id for the run.
type RunRegisterResponse struct {
	RunID int64 `json:"run_id"`
}

// Progress is a periodic progress snapshot.
type Progress struct {
	Phase          string `json:"phase"` // "snapshot", "upload", "restore", ...
	Files          int64  `json:"files"`
	Dirs           int64  `json:"dirs"`
	BytesRead      uint64 `json:"bytes_read"`
	BytesUploaded  uint64 `json:"bytes_uploaded"`
	BytesTotal     uint64 `json:"bytes_total,omitempty"`
	CurrentArchive string `json:"current_archive,omitempty"`
	Skipped        int64  `json:"skipped"`
}

// Result is the final outcome of a run.
type Result struct {
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
	Snapshot      string `json:"snapshot,omitempty"` // host/<id>/<RFC3339>
	BackupTime    int64  `json:"backup_time,omitempty"`
	BytesTotal    uint64 `json:"bytes_total"`
	BytesUploaded uint64 `json:"bytes_uploaded"`
	ChunksNew     int    `json:"chunks_new"`
	ChunksReused  int    `json:"chunks_reused"`
	Files         int64  `json:"files"`
	Skipped       int64  `json:"skipped"`
}

// Event is posted by the agent while a run executes.
type Event struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // "log" | "progress" | "result"
	Level    string    `json:"level,omitempty"`
	Message  string    `json:"message,omitempty"`
	Progress *Progress `json:"progress,omitempty"`
	Result   *Result   `json:"result,omitempty"`
}

// EnrollRequest is sent with a one-time enrollment code or a setup token.
type EnrollRequest struct {
	Code     string `json:"code"`
	CSR      string `json:"csr"` // PEM
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	// ClientName is the name chosen on the PC; only setup tokens use it
	// (a one-time code carries its own name).
	ClientName string `json:"client_name,omitempty"`
}

// EnrollResponse returns the signed client certificate.
type EnrollResponse struct {
	ClientID   int64  `json:"client_id"`
	ClientName string `json:"client_name"`
	CertPEM    string `json:"cert_pem"`
	CAPEM      string `json:"ca_pem"`
}

// EnrollmentToken is the string an admin pastes into the agent: base64url(JSON).
type EnrollmentToken struct {
	URL           string `json:"u"`
	Code          string `json:"c"`
	CAFingerprint string `json:"f"` // sha256 of the server CA cert (hex)
	// Setup tokens only: valid for many PCs until Expires (unix seconds);
	// Host is the console address the setup offers as default.
	Multi   bool   `json:"m,omitempty"`
	Expires int64  `json:"e,omitempty"`
	Host    string `json:"h,omitempty"`
}

// RestoreSessionRequest asks the console for a self-service restore page for
// a PC user (POST /agent/v1/restore-sessions). The agent determines the user
// from the tray app's named pipe connection, not from anything the tray sends.
type RestoreSessionRequest struct {
	Ref   string `json:"ref"`   // agent-side session reference, echoed in RestoreSpec.Session
	User  string `json:"user"`  // DOMAIN\name
	SID   string `json:"sid"`   // user SID
	Admin bool   `json:"admin"` // member of the local Administrators group
	// Scope is the folder the user may browse and restore (their profile
	// folder); empty for administrators, who may restore everything.
	Scope string `json:"scope"`
	// TTL is how long the agent keeps the session (seconds).
	TTL int64 `json:"ttl"`
}

// RestoreSessionResponse carries the page the tray app opens.
type RestoreSessionResponse struct {
	URL     string `json:"url"`
	Expires int64  `json:"expires"`
}
