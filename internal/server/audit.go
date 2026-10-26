// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The audit log records sign-ins and every change made through the console
// API (and a few sensitive reads, such as key downloads): who, when, what and
// whether it succeeded. Handlers name what a request applied to with
// auditTarget and add details with auditDetail.

// auditRetention is how long audit entries are kept.
const auditRetention = 2 * 365 * 24 * time.Hour

type auditInfo struct {
	pattern string // route pattern, e.g. "PUT /api/targets/{id}"
	target  string
	detail  string
	force   bool // record even though it is a GET
}

func auditOf(r *http.Request) *auditInfo {
	ai, _ := r.Context().Value(auditKey).(*auditInfo)
	if ai == nil {
		return &auditInfo{} // not a console session (tests)
	}
	return ai
}

// noteRoute remembers the matched route pattern of the request.
func noteRoute(r *http.Request) {
	ai := auditOf(r)
	ai.pattern = r.Pattern
	if sensitiveReads[r.Pattern] {
		ai.force = true
	}
}

// auditTarget names what the request applies to, e.g. "client pc-01".
func auditTarget(r *http.Request, target string) { auditOf(r).target = target }

// auditDetail adds a description of the change.
func auditDetail(r *http.Request, format string, args ...any) {
	auditOf(r).detail = fmt.Sprintf(format, args...)
}

// sensitiveReads are GET routes that are recorded too.
var sensitiveReads = map[string]bool{
	"GET /api/clients/{id}/encryption-key":       true,
	"GET /api/enrollments/{id}/command":          true,
	"GET /api/setup-tokens/{id}":                 true,
	"GET /api/setup-tokens/{id}/download/{arch}": true,
}

// auditActions are readable names of the audited routes.
var auditActions = map[string]string{
	"POST /api/password":                         "change own password",
	"POST /api/targets":                          "add PBS server",
	"PUT /api/targets/{id}":                      "change PBS server",
	"DELETE /api/targets/{id}":                   "remove PBS server",
	"POST /api/targets/test":                     "test PBS server",
	"DELETE /api/clients/{id}":                   "revoke client",
	"POST /api/clients/{id}/unrevoke":            "restore revoked client",
	"POST /api/clients/{id}/agent-update":        "push agent update",
	"POST /api/clients/{id}/rotate-credentials":  "rotate client credentials",
	"POST /api/clients/rotate-credentials":       "rotate credentials of clients",
	"POST /api/clients/{id}/restore":             "start restore",
	"GET /api/clients/{id}/encryption-key":       "download client encryption key",
	"PUT /api/clients/{id}/tags":                 "change client tags",
	"POST /api/enrollments":                      "create enrollment",
	"GET /api/enrollments/{id}/command":          "show enrollment command",
	"DELETE /api/enrollments/{id}":               "cancel enrollment",
	"POST /api/setup-tokens":                     "create setup token",
	"GET /api/setup-tokens/{id}":                 "show setup token",
	"GET /api/setup-tokens/{id}/download/{arch}": "download agent setup",
	"DELETE /api/setup-tokens/{id}":              "revoke setup token",
	"PUT /api/jobs/{id}":                         "change member job",
	"DELETE /api/jobs/{id}":                      "remove client from job",
	"POST /api/jobs/{id}/run":                    "start backup",
	"POST /api/group-jobs":                       "create job",
	"PUT /api/group-jobs/{id}":                   "change job",
	"DELETE /api/group-jobs/{id}":                "delete job",
	"POST /api/group-jobs/{id}/run":              "start job on all clients",
	"POST /api/runs/{id}/cancel":                 "cancel run",
	"PUT /api/settings/notifications":            "change notification settings",
	"POST /api/settings/notifications/test":      "send test notification",
	"PUT /api/settings/updates":                  "change update settings",
	"PUT /api/settings/encryption":               "change encryption master key",
	"POST /api/updates/check":                    "check for updates",
	"POST /api/updates/install":                  "install console update",
	"POST /api/users":                            "create user",
	"PUT /api/users/{id}":                        "change user",
	"DELETE /api/users/{id}":                     "delete user",
	"POST /api/users/{id}/password":              "reset user password",
	"POST /api/roles":                            "create role",
	"PUT /api/roles/{id}":                        "change role",
	"DELETE /api/roles/{id}":                     "delete role",
}

func (s *Server) recordAudit(r *http.Request, u *SessionUser, ai *auditInfo, status int) {
	action := auditActions[ai.pattern]
	if action == "" {
		action = ai.pattern
	}
	target := ai.target
	if target == "" && r.PathValue("id") != "" {
		target = r.URL.Path
	}
	e := &AuditEntry{UserID: u.ID, Username: u.Name, Action: action, Target: target, Detail: ai.detail, Status: status, IP: clientIP(r)}
	if err := s.store.AddAudit(r.Context(), e); err != nil {
		s.log.Error("audit log", "err", err)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := AuditFilter{User: q.Get("user")}
	f.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	es, err := s.store.AuditLog(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, orEmpty(es))
}
