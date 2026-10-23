// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"proxbackup/pkg/pbs"
)

// The dashboard's storage graphs: datastore usage of each PBS server (now and
// over time, from the PBS RRD) and the data each client keeps there.

var storageTimeframes = []string{"day", "week", "month", "year"}

// storageTTL is how long a PBS answer is reused; the dashboard polls often.
const storageTTL = time.Minute

type storageCache struct {
	mu sync.Mutex
	m  map[string]storageEntry // "<target id>/<timeframe>"
}

type storageEntry struct {
	at  time.Time
	val targetStorage
}

type storagePoint struct {
	Time  int64   `json:"t"`
	Used  float64 `json:"used"`
	Total float64 `json:"total"`
}

type clientUsage struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Protected uint64 `json:"protected"`
	Uploaded  uint64 `json:"uploaded_30d"`
}

type targetStorage struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Datastore string         `json:"datastore"`
	Total     uint64         `json:"total"`
	Used      uint64         `json:"used"`
	Avail     uint64         `json:"avail"`
	History   []storagePoint `json:"history"`
	Error     string         `json:"error,omitempty"`
	Clients   []clientUsage  `json:"clients"`
}

// targetStorage reads the usage of t from its PBS, cached for storageTTL.
func (s *Server) targetStorage(ctx context.Context, t *Target, timeframe string) targetStorage {
	key := fmt.Sprintf("%d/%s", t.ID, timeframe)
	s.storage.mu.Lock()
	e, ok := s.storage.m[key]
	s.storage.mu.Unlock()
	if ok && time.Since(e.at) < storageTTL {
		return e.val
	}
	v := targetStorage{ID: t.ID, Name: t.Name, Datastore: t.Datastore, History: []storagePoint{}}
	err := func() error {
		pc, err := s.adminClient(t)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		st, err := pc.DatastoreStatus(ctx, t.Datastore)
		if err != nil {
			return err
		}
		v.Total, v.Used, v.Avail = st.Total, st.Used, st.Avail
		pts, err := pc.DatastoreRRD(ctx, t.Datastore, timeframe)
		if err != nil {
			return err
		}
		v.History = rrdHistory(pts, historyPoints)
		return nil
	}()
	if err != nil {
		v.Error = err.Error()
	}
	s.storage.mu.Lock()
	if s.storage.m == nil {
		s.storage.m = map[string]storageEntry{}
	}
	s.storage.m[key] = storageEntry{time.Now(), v}
	s.storage.mu.Unlock()
	return v
}

// historyPoints caps the samples sent to the browser; PBS returns up to 1440.
const historyPoints = 360

// rrdHistory keeps the samples PBS has data for, averaged down to at most max.
func rrdHistory(pts []pbs.RRDPoint, max int) []storagePoint {
	var all []storagePoint
	for _, p := range pts {
		if p.Used != nil && p.Total != nil {
			all = append(all, storagePoint{p.Time, *p.Used, *p.Total})
		}
	}
	out := []storagePoint{}
	n := (len(all) + max - 1) / max // samples per bucket
	for i := 0; i < len(all); i += n {
		b := all[i:min(i+n, len(all))]
		var sp storagePoint
		for _, p := range b {
			sp.Used += p.Used
			sp.Total += p.Total
		}
		sp.Time = b[len(b)-1].Time
		sp.Used /= float64(len(b))
		sp.Total /= float64(len(b))
		out = append(out, sp)
	}
	return out
}

// handleStorage lists the PBS servers holding clients the user may see, with
// their datastore usage and the data of each of those clients.
func (s *Server) handleStorage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a := access(r)
	tf := r.URL.Query().Get("timeframe")
	if !slices.Contains(storageTimeframes, tf) {
		tf = "week"
	}
	targets, err := s.store.Targets(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	clients, err := s.store.Clients(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	usage, err := s.store.ClientStorage(ctx, time.Now().Add(-30*24*time.Hour).Unix())
	if err != nil {
		httpError(w, 500, err)
		return
	}
	byTarget := map[int64][]clientUsage{}
	for _, c := range clients {
		if !a.Client(PermViewClients, c) {
			continue
		}
		u := clientUsage{ID: c.ID, Name: c.Name}
		if cs := usage[c.ID]; cs != nil {
			u.Protected, u.Uploaded = cs.Protected, cs.Uploaded
		}
		byTarget[c.TargetID] = append(byTarget[c.TargetID], u)
	}
	global := a.Global(PermViewClients)
	out := []targetStorage{}
	for _, t := range targets {
		cs, ok := byTarget[t.ID]
		if !ok && !global {
			continue
		}
		v := s.targetStorage(ctx, t, tf)
		slices.SortFunc(cs, func(x, y clientUsage) int { return cmp.Compare(y.Protected, x.Protected) })
		v.Clients = orEmpty(cs)
		out = append(out, v)
	}
	writeJSON(w, out)
}
