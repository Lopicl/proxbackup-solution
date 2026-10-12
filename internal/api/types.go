// Package api defines the JSON contract between pbspc-agent and pbspc-server.
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
	RunLost       = "lost" // agent stopped reporting
)

// Terminal reports whether a run state is final.
func Terminal(state string) bool {
	switch state {
	case RunSuccess, RunWarning, RunFailed, RunCanceled, RunLost:
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

// RestoreSpec describes a restore job.
type RestoreSpec struct {
	BackupID   string   `json:"backup_id"`
	BackupTime int64    `json:"backup_time"`
	Archive    string   `json:"archive"`         // e.g. "c-users.pxar.didx"
	Paths      []string `json:"paths,omitempty"` // archive-relative paths; empty = everything
	TargetDir  string   `json:"target_dir"`      // where to restore to
	Overwrite  string   `json:"overwrite"`       // "skip" | "overwrite" | "if-newer"
	TargetDisk string   `json:"target_disk,omitempty"`
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
	// image
	Volumes []string `json:"volumes,omitempty"` // e.g. "C:"
	// restore
	Restore *RestoreSpec `json:"restore,omitempty"`
}

// PollRequest is the agent heartbeat.
type PollRequest struct {
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`
	AgentVersion string  `json:"agent_version"`
	RunningRuns  []int64 `json:"running_runs"`
}

// PollResponse carries new work and cancellations.
type PollResponse struct {
	Jobs   []JobSpec `json:"jobs"`
	Cancel []int64   `json:"cancel"`
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

// EnrollRequest is sent with a one-time enrollment code.
type EnrollRequest struct {
	Code     string `json:"code"`
	CSR      string `json:"csr"` // PEM
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
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
}
