package server

import (
	"context"
	"sync"

	"github.com/robfig/cron/v3"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ValidateSchedule checks a cron expression ("30 21 * * 1-5", "@daily", "@every 6h").
func ValidateSchedule(spec string) error {
	_, err := cronParser.Parse(spec)
	return err
}

// Scheduler queues runs for enabled jobs according to their cron schedule.
// Runs for offline clients stay queued until the agent polls again.
type Scheduler struct {
	s       *Server
	mu      sync.Mutex
	cron    *cron.Cron
	entries map[int64]cron.EntryID
}

func NewScheduler(s *Server) *Scheduler {
	return &Scheduler{s: s, cron: cron.New(cron.WithParser(cronParser)), entries: map[int64]cron.EntryID{}}
}

func (sc *Scheduler) Start() { sc.cron.Start() }
func (sc *Scheduler) Stop()  { sc.cron.Stop() }

// Reload re-reads all jobs and rebuilds the schedule.
func (sc *Scheduler) Reload(ctx context.Context) error {
	jobs, err := sc.s.store.Jobs(ctx, 0)
	if err != nil {
		return err
	}
	clients, err := sc.s.store.Clients(ctx)
	if err != nil {
		return err
	}
	active := map[int64]bool{}
	for _, c := range clients {
		active[c.ID] = true
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, id := range sc.entries {
		sc.cron.Remove(id)
	}
	sc.entries = map[int64]cron.EntryID{}
	for _, j := range jobs {
		if !j.Enabled || j.Schedule == "" || !active[j.ClientID] {
			continue
		}
		jobID := j.ID
		eid, err := sc.cron.AddFunc(j.Schedule, func() {
			ctx := context.Background()
			if runID, err := sc.s.queueJob(ctx, jobID, "schedule"); err != nil {
				sc.s.log.Info("scheduled run skipped", "job", jobID, "reason", err)
			} else {
				sc.s.log.Info("scheduled run queued", "job", jobID, "run", runID)
			}
		})
		if err != nil {
			sc.s.log.Warn("invalid schedule", "job", j.ID, "schedule", j.Schedule, "err", err)
			continue
		}
		sc.entries[j.ID] = eid
	}
	return nil
}

// Next returns the next scheduled time of a job (unix seconds) or 0.
func (sc *Scheduler) Next(jobID int64) int64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	id, ok := sc.entries[jobID]
	if !ok {
		return 0
	}
	if e := sc.cron.Entry(id); !e.Next.IsZero() {
		return e.Next.Unix()
	}
	return 0
}
