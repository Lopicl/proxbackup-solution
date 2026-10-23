// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Admin API helpers used by the management server (requires a privileged token).

// Version returns the PBS version info.
func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	var v map[string]any
	err := c.Call(ctx, http.MethodGet, "version", nil, &v)
	return v, err
}

// SnapshotInfo is an item of the datastore snapshot list.
type SnapshotInfo struct {
	BackupType string `json:"backup-type"`
	BackupID   string `json:"backup-id"`
	BackupTime int64  `json:"backup-time"`
	Size       uint64 `json:"size"`
	Owner      string `json:"owner"`
	Protected  bool   `json:"protected"`
	Comment    string `json:"comment"`
	Files      []struct {
		Filename  string `json:"filename"`
		Size      uint64 `json:"size"`
		CryptMode string `json:"crypt-mode"`
	} `json:"files"`
	Verification *struct {
		State string `json:"state"`
		Upid  string `json:"upid"`
	} `json:"verification"`
}

// ListSnapshots lists snapshots of a group (or all groups if id is empty).
func (c *Client) ListSnapshots(ctx context.Context, store, ns, btype, id string) ([]SnapshotInfo, error) {
	params := map[string]any{}
	if ns != "" {
		params["ns"] = ns
	}
	if btype != "" {
		params["backup-type"] = btype
	}
	if id != "" {
		params["backup-id"] = id
	}
	var out []SnapshotInfo
	err := c.Call(ctx, http.MethodGet, "admin/datastore/"+url.PathEscape(store)+"/snapshots", params, &out)
	return out, err
}

// SetProtected sets or clears the protected flag of a snapshot. PBS refuses to
// prune or forget protected snapshots.
func (c *Client) SetProtected(ctx context.Context, store, ns, btype, id string, backupTime int64, protected bool) error {
	params := map[string]any{"backup-type": btype, "backup-id": id, "backup-time": backupTime, "protected": protected}
	if ns != "" {
		params["ns"] = ns
	}
	return c.Call(ctx, http.MethodPut, "admin/datastore/"+url.PathEscape(store)+"/protected", params, nil)
}

// ForgetSnapshot deletes one snapshot. PBS refuses for protected snapshots.
func (c *Client) ForgetSnapshot(ctx context.Context, store, ns, btype, id string, backupTime int64) error {
	params := map[string]any{"backup-type": btype, "backup-id": id, "backup-time": backupTime}
	if ns != "" {
		params["ns"] = ns
	}
	return c.Call(ctx, http.MethodDelete, "admin/datastore/"+url.PathEscape(store)+"/snapshots", params, nil)
}

// Finished reports whether the snapshot has its manifest (the backup completed).
func (s SnapshotInfo) Finished() bool {
	for _, f := range s.Files {
		if f.Filename == "index.json.blob" {
			return true
		}
	}
	return false
}

// KeepOptions is a PBS retention policy. Zero values are omitted.
type KeepOptions struct {
	Last    int `json:"keep-last,omitempty"`
	Hourly  int `json:"keep-hourly,omitempty"`
	Daily   int `json:"keep-daily,omitempty"`
	Weekly  int `json:"keep-weekly,omitempty"`
	Monthly int `json:"keep-monthly,omitempty"`
	Yearly  int `json:"keep-yearly,omitempty"`
}

// IsZero reports whether no retention is configured (prune would keep nothing).
func (k KeepOptions) IsZero() bool { return k == KeepOptions{} }

// PruneResult is one item returned by the prune API.
type PruneResult struct {
	BackupType string `json:"backup-type"`
	BackupID   string `json:"backup-id"`
	BackupTime int64  `json:"backup-time"`
	Keep       bool   `json:"keep"`
	Protected  bool   `json:"protected"`
}

// PruneGroup applies keep to one backup group.
func (c *Client) PruneGroup(ctx context.Context, store, ns, btype, id string, keep KeepOptions, dryRun bool) ([]PruneResult, error) {
	params := map[string]any{"backup-type": btype, "backup-id": id, "dry-run": dryRun}
	if ns != "" {
		params["ns"] = ns
	}
	add := func(k string, v int) {
		if v > 0 {
			params[k] = v
		}
	}
	add("keep-last", keep.Last)
	add("keep-hourly", keep.Hourly)
	add("keep-daily", keep.Daily)
	add("keep-weekly", keep.Weekly)
	add("keep-monthly", keep.Monthly)
	add("keep-yearly", keep.Yearly)
	var out []PruneResult
	err := c.Call(ctx, http.MethodPost, "admin/datastore/"+url.PathEscape(store)+"/prune", params, &out)
	return out, err
}

// EnsureNamespace creates every component of ns (e.g. "pcs/office/pc-01") if missing.
func (c *Client) EnsureNamespace(ctx context.Context, store, ns string) error {
	if ns == "" {
		return nil
	}
	var existing []struct {
		NS string `json:"ns"`
	}
	if err := c.Call(ctx, http.MethodGet, "admin/datastore/"+url.PathEscape(store)+"/namespace", nil, &existing); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, e := range existing {
		have[e.NS] = true
	}
	parent := ""
	for _, part := range strings.Split(ns, "/") {
		full := part
		if parent != "" {
			full = parent + "/" + part
		}
		if !have[full] {
			params := map[string]any{"name": part}
			if parent != "" {
				params["parent"] = parent
			}
			if err := c.Call(ctx, http.MethodPost, "admin/datastore/"+url.PathEscape(store)+"/namespace", params, nil); err != nil {
				return err
			}
		}
		parent = full
	}
	return nil
}

// EnsureUser creates a PBS realm user (e.g. "proxbackup@pbs") if it does not exist.
func (c *Client) EnsureUser(ctx context.Context, userid, comment string) error {
	err := c.Call(ctx, http.MethodGet, "access/users/"+url.PathEscape(userid), nil, nil)
	if err == nil {
		return nil
	}
	return c.Call(ctx, http.MethodPost, "access/users", map[string]any{"userid": userid, "comment": comment}, nil)
}

// CreateToken creates an API token for userid and returns (tokenid, secret).
func (c *Client) CreateToken(ctx context.Context, userid, name, comment string) (string, string, error) {
	var out struct {
		TokenID string `json:"tokenid"`
		Value   string `json:"value"`
	}
	path := "access/users/" + url.PathEscape(userid) + "/token/" + url.PathEscape(name)
	err := c.Call(ctx, http.MethodPost, path, map[string]any{"comment": comment}, &out)
	return out.TokenID, out.Value, err
}

// DeleteToken removes an API token.
func (c *Client) DeleteToken(ctx context.Context, userid, name string) error {
	path := "access/users/" + url.PathEscape(userid) + "/token/" + url.PathEscape(name)
	return c.Call(ctx, http.MethodDelete, path, nil, nil)
}

// GrantACL grants role on path to an auth id (user or token).
func (c *Client) GrantACL(ctx context.Context, path, role, authID string) error {
	params := map[string]any{"path": path, "role": role, "auth-id": authID, "propagate": true}
	return c.Call(ctx, http.MethodPut, "access/acl", params, nil)
}

// DatastoreACLPath renders the ACL path for a datastore namespace.
func DatastoreACLPath(store, ns string) string {
	p := "/datastore/" + store
	if ns != "" {
		p += "/" + ns
	}
	return p
}

// DatastoreStatus is the current space usage of a datastore, in bytes.
type DatastoreStatus struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Avail uint64 `json:"avail"`
}

// DatastoreStatus returns the current space usage of store.
func (c *Client) DatastoreStatus(ctx context.Context, store string) (*DatastoreStatus, error) {
	var out DatastoreStatus
	err := c.Call(ctx, http.MethodGet, "admin/datastore/"+url.PathEscape(store)+"/status", nil, &out)
	return &out, err
}

// RRDPoint is a sample of a datastore's usage history. PBS leaves the values
// out where it has no data, hence the pointers.
type RRDPoint struct {
	Time      int64    `json:"time"`
	Total     *float64 `json:"total"`
	Used      *float64 `json:"used"`
	Available *float64 `json:"available"`
}

// DatastoreRRD returns the usage history of store over timeframe (hour, day,
// week, month or year), averaged per sample.
func (c *Client) DatastoreRRD(ctx context.Context, store, timeframe string) ([]RRDPoint, error) {
	var out []RRDPoint
	err := c.Call(ctx, http.MethodGet, "admin/datastore/"+url.PathEscape(store)+"/rrd",
		map[string]any{"timeframe": timeframe, "cf": "AVERAGE"}, &out)
	return out, err
}
