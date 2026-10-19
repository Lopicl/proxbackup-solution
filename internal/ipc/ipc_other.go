// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package ipc

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
)

// socketName is the Unix socket in the data directory used outside Windows
// (development and tests).
const socketName = "agent.sock"

// Listen creates the agent's socket in dataDir.
func Listen(dataDir string) (net.Listener, error) {
	p := filepath.Join(dataDir, socketName)
	os.Remove(p)
	return net.Listen("unix", p)
}

func dial(ctx context.Context, dataDir string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", filepath.Join(dataDir, socketName))
}

type peerToken struct{}

// peerOf reports the current user: only that user can reach a socket in the
// (private) data directory.
func peerOf(net.Conn) (*Peer, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return &Peer{User: u.Username, SID: u.Uid, Profile: u.HomeDir, Admin: u.Uid == "0"}, nil
}

// Keep returns a copy of the peer that stays valid after the request.
func (p *Peer) Keep() (*Peer, error) { k := *p; return &k, nil }

// Close releases the peer.
func (p *Peer) Close() {}

// RunAs runs fn (there is no impersonation outside Windows).
func (p *Peer) RunAs(fn func() error) error { return fn() }
