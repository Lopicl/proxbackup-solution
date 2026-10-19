// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// The restore browser lists a snapshot's catalog.pcat1.didx. A catalog is
// downloaded once into a temp file and kept while it is being browsed, so
// opening a folder doesn't start a PBS reader session each time.

const (
	catalogIdle    = 10 * time.Minute
	catalogMaxOpen = 8
)

var errNoCatalog = errors.New("this snapshot has no file catalog (it was taken by an older agent, or building the catalog failed)")

type catalogCache struct {
	mu      sync.Mutex
	entries map[string]*cachedCatalog
}

type cachedCatalog struct {
	ready chan struct{} // closed once loaded (or failed)
	f     *os.File
	r     *pbs.CatalogReader
	err   error
	used  time.Time
}

func (c *cachedCatalog) close() {
	if c.f != nil {
		c.f.Close()
		os.Remove(c.f.Name())
	}
}

// get returns the cached catalog for key, loading it with load on a miss.
// Concurrent requests for the same snapshot share one download; failures
// aren't cached.
func (cc *catalogCache) get(ctx context.Context, key string, load func(context.Context) (*os.File, error)) (*pbs.CatalogReader, error) {
	cc.mu.Lock()
	if cc.entries == nil {
		cc.entries = map[string]*cachedCatalog{}
	}
	cc.evictLocked(time.Now())
	e, ok := cc.entries[key]
	if !ok {
		e = &cachedCatalog{ready: make(chan struct{}), used: time.Now()}
		cc.entries[key] = e
		go func() {
			// Not tied to the request: a reload of the page shouldn't abort a download others wait for.
			lctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			f, err := load(lctx)
			if err == nil {
				var st os.FileInfo
				if st, err = f.Stat(); err == nil {
					e.r, err = pbs.NewCatalogReader(f, st.Size())
				}
				e.f = f
			}
			cc.mu.Lock()
			e.err = err
			if err != nil {
				e.close()
				if cc.entries[key] == e {
					delete(cc.entries, key)
				}
			}
			cc.mu.Unlock()
			close(e.ready)
		}()
	}
	e.used = time.Now()
	cc.mu.Unlock()
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return e.r, e.err
}

// evictLocked drops idle catalogs and, above catalogMaxOpen, the least recently used.
func (cc *catalogCache) evictLocked(now time.Time) {
	loaded := func(e *cachedCatalog) bool {
		select {
		case <-e.ready:
			return e.err == nil
		default:
			return false
		}
	}
	for k, e := range cc.entries {
		if loaded(e) && now.Sub(e.used) > catalogIdle {
			e.close()
			delete(cc.entries, k)
		}
	}
	for len(cc.entries) >= catalogMaxOpen {
		var oldest string
		for k, e := range cc.entries {
			if loaded(e) && (oldest == "" || e.used.Before(cc.entries[oldest].used)) {
				oldest = k
			}
		}
		if oldest == "" {
			return
		}
		cc.entries[oldest].close()
		delete(cc.entries, oldest)
	}
}

// catalogEntry is one row of the restore browser.
type catalogEntry struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // "dir", "file", "symlink" or "other"
	Size  uint64 `json:"size,omitempty"`
	Mtime int64  `json:"mtime,omitempty"`
	// Origin is, for the archives at the catalog root, the path on the PC
	// the archive was backed up from (as configured in the client's jobs).
	Origin string `json:"origin,omitempty"`
}

// handleCatalog lists one directory of a snapshot's catalog:
// GET /api/clients/{id}/catalog?ns=&backup_id=&backup_time=&path=/archive/dir
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	c, err := s.store.Client(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	out, code, err := s.catalogDir(r.Context(), c, r.URL.Query())
	if err != nil {
		httpError(w, code, err)
		return
	}
	writeJSON(w, out)
}

// catalogDir lists the directory q["path"] of the snapshot q identifies. On
// error it also returns an HTTP status.
func (s *Server) catalogDir(ctx context.Context, c *Client, q url.Values) ([]catalogEntry, int, error) {
	backupID, ns, dir := q.Get("backup_id"), q.Get("ns"), q.Get("path")
	backupTime, _ := strconv.ParseInt(q.Get("backup_time"), 10, 64)
	if backupID == "" || backupTime == 0 {
		return nil, 400, errors.New("backup_id and backup_time are required")
	}
	if ns == "" {
		ns = c.Namespace
	} else if ns != c.Namespace && !slices.Contains(c.OldNamespaces, ns) {
		return nil, 400, errors.New("snapshot namespace does not belong to this client")
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, 500, err
	}
	ref := pbs.SnapshotRef{Store: t.Datastore, NS: ns, Type: "host", ID: backupID, Time: backupTime}
	key := fmt.Sprintf("%d|%s|%s|%s|%d", t.ID, t.Datastore, ns, backupID, backupTime)
	cat, err := s.catalogs.get(ctx, key, func(ctx context.Context) (*os.File, error) { return s.downloadCatalog(ctx, t, c, ref) })
	if errors.Is(err, errNoCatalog) {
		return nil, 404, err
	}
	if err != nil {
		return nil, 502, err
	}
	list, err := cat.ListDir(dir)
	if err != nil {
		return nil, 404, err
	}
	var origins map[string]string
	if strings.Trim(dir, "/") == "" {
		origins = s.archiveOrigins(ctx, c.ID, backupID)
	}
	out := make([]catalogEntry, 0, len(list))
	for _, e := range list {
		ce := catalogEntry{Name: e.Name, Origin: origins[e.Name]}
		switch e.Type {
		case pbs.CatalogDir:
			ce.Type = "dir"
		case pbs.CatalogFile:
			ce.Type, ce.Size, ce.Mtime = "file", e.Size, e.Mtime
		case pbs.CatalogSymlink:
			ce.Type = "symlink"
		default:
			ce.Type = "other"
		}
		out = append(out, ce)
	}
	return out, 0, nil
}

// downloadCatalog copies ref's catalog into a temp file.
func (s *Server) downloadCatalog(ctx context.Context, t *Target, c *Client, ref pbs.SnapshotRef) (*os.File, error) {
	pc, err := s.adminClient(t)
	if err != nil {
		return nil, err
	}
	var crypt *pbs.CryptConfig
	if k, err := s.clientKey(ctx, c); err != nil {
		return nil, err
	} else if k != nil {
		raw, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("invalid client encryption key")
		}
		if crypt, err = pbs.NewCryptConfig([32]byte(raw)); err != nil {
			return nil, err
		}
	}
	rs, err := pc.StartReader(ctx, ref, crypt)
	if err != nil {
		return nil, fmt.Errorf("open snapshot %s: %w", ref, err)
	}
	defer rs.Close()
	m, err := rs.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(m.Files, func(f pbs.FileInfo) bool { return f.Filename == pbs.CatalogArchiveName })
	if i < 0 {
		return nil, errNoCatalog
	}
	if m.Files[i].CryptMode == "encrypt" && crypt == nil {
		return nil, fmt.Errorf("snapshot %s is encrypted (key %s), but this client has no encryption key", ref, m.KeyFingerprint())
	}
	idx, err := rs.Index(ctx, pbs.CatalogArchiveName, &m.Files[i])
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "proxbackup-catalog-*")
	if err != nil {
		return nil, err
	}
	stream := rs.OpenIndex(ctx, idx, 4)
	_, err = io.Copy(f, stream)
	stream.Close()
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("download catalog: %w", err)
	}
	return f, nil
}

// archiveOrigins maps the archive names the client's jobs with backupID
// write to the path they back up, so a restore can go back to the original
// location. It follows the current job configuration: an archive whose source
// was removed since has no origin.
func (s *Server) archiveOrigins(ctx context.Context, clientID int64, backupID string) map[string]string {
	jobs, err := s.store.Jobs(ctx, clientID)
	if err != nil {
		return nil
	}
	m := map[string]string{}
	add := func(archive, origin string) {
		if _, ok := m[archive]; !ok {
			m[archive] = origin
		}
	}
	for _, j := range jobs {
		if j.BackupID != backupID {
			continue
		}
		switch j.Kind {
		case api.KindFiles:
			for a, src := range api.SourceArchives(j.Sources) {
				add(a, src)
			}
		case api.KindImage:
			for _, v := range j.Volumes {
				add(api.VolumeArchive(v), api.OriginPath(v, ""))
			}
		}
	}
	return m
}
