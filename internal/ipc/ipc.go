// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipc is the local channel between the agent service and the tray
// app: a named pipe (\\.\pipe\proxbackup-agent) on Windows, a Unix socket in
// the agent's data directory elsewhere (development). Each connection carries
// one JSON request and one JSON response.
//
// The pipe's ACL admits SYSTEM and interactive users only, and the agent
// identifies the user from the connection itself (Peer), never from what the
// tray sends.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"proxbackup/internal/api"
)

// PipeName is the agent's named pipe on Windows, served by the service ServiceName.
const (
	PipeName    = `\\.\pipe\proxbackup-agent`
	ServiceName = "proxbackup-agent"
)

// Exit codes of the tray app that tell the agent's launcher what to do.
const (
	TrayExitQuit      = 0 // the user quit: don't start it again in this session
	TrayExitDuplicate = 3 // another tray already runs in the session
	TrayExitRestart   = 4 // the agent was updated: start the new version
)

// Operations.
const (
	OpStatus      = "status"
	OpBackupNow   = "backup-now"
	OpPause       = "pause"
	OpResume      = "resume"
	OpRestoreLink = "restore-link"
)

// Request is what the tray sends.
type Request struct {
	Op      string `json:"op"`
	Minutes int    `json:"minutes,omitempty"` // OpPause
}

// Response is the agent's answer.
type Response struct {
	Error   string  `json:"error,omitempty"`
	Message string  `json:"message,omitempty"`
	Status  *Status `json:"status,omitempty"` // OpStatus
	URL     string  `json:"url,omitempty"`    // OpRestoreLink
}

// Status is the agent's state as the tray shows it.
type Status struct {
	Version    string `json:"version"`
	Exe        string `json:"exe"` // the agent's executable: a tray of an older version restarts from it
	Client     string `json:"client"`
	Server     string `json:"server"`
	User       string `json:"user"`  // the connected user, as the agent identified them
	Admin      bool   `json:"admin"` // ... and whether they may restore everything
	Online     bool   `json:"online"`
	Configured bool   `json:"configured"` // a job configuration was received
	// PausedUntil (unix seconds) while scheduled backups are paused.
	PausedUntil int64       `json:"paused_until,omitempty"`
	PausedBy    string      `json:"paused_by,omitempty"`
	Running     *RunningRun `json:"running,omitempty"`
	Jobs        []Job       `json:"jobs"`
	Recent      []RunInfo   `json:"recent"` // newest first
}

// Job is a backup job of this PC.
type Job struct {
	ID      int64    `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	NextRun int64    `json:"next_run,omitempty"`
	LastRun *RunInfo `json:"last_run,omitempty"`
}

// RunInfo is a finished run.
type RunInfo struct {
	JobID    int64  `json:"job_id"`
	JobName  string `json:"job_name"`
	Kind     string `json:"kind"`
	Trigger  string `json:"trigger"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
	Files    int64  `json:"files"`
	Bytes    uint64 `json:"bytes"`
}

// RunningRun is the run in progress.
type RunningRun struct {
	JobName  string       `json:"job_name"`
	Kind     string       `json:"kind"`
	Trigger  string       `json:"trigger"`
	Started  int64        `json:"started"`
	Progress api.Progress `json:"progress"`
}

// Peer is the user on the other end of a connection. Close releases it.
type Peer struct {
	User    string // DOMAIN\name
	SID     string
	Profile string // profile folder, e.g. C:\Users\alice
	Admin   bool   // member of the local Administrators group (elevated or not)
	token   peerToken
}

// Handler answers one request from peer.
type Handler func(ctx context.Context, peer *Peer, req Request) Response

// Serve accepts connections on l until ctx ends. The peer is closed when the
// handler returns; a handler that needs it longer takes a copy with Keep.
func Serve(ctx context.Context, l net.Listener, h Handler) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go serveConn(ctx, c, h)
	}
}

func serveConn(ctx context.Context, c net.Conn, h Handler) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		return
	}
	// Identify the caller now: impersonating a pipe client needs data read from it first.
	peer, err := peerOf(c)
	var resp Response
	if err != nil {
		resp.Error = "cannot identify the user: " + err.Error()
	} else {
		resp = h(ctx, peer, req)
		peer.Close()
	}
	json.NewEncoder(c).Encode(resp)
}

// Call sends req to the agent and returns its response. dataDir only matters
// outside Windows.
func Call(ctx context.Context, dataDir string, req Request) (*Response, error) {
	c, err := dial(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}
