// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, permissions)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.store.Users(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, orEmpty(us))
}

// cleanAssignments checks role assignments and normalizes their scopes.
func (s *Server) cleanAssignments(r *http.Request, in []RoleAssignment) ([]RoleAssignment, error) {
	out := []RoleAssignment{}
	for _, a := range in {
		role, err := s.store.Role(r.Context(), a.RoleID)
		if err != nil {
			return nil, fmt.Errorf("unknown role %d", a.RoleID)
		}
		a.RoleName = role.Name
		if a.AllClients {
			a.Clients, a.Tags = []int64{}, []string{}
			out = append(out, a)
			continue
		}
		clients := []int64{}
		for _, id := range a.Clients {
			if _, err := s.store.Client(r.Context(), id); err != nil {
				return nil, fmt.Errorf("unknown client %d", id)
			}
			if !slices.Contains(clients, id) {
				clients = append(clients, id)
			}
		}
		tags := []string{}
		for _, t := range cleanList(a.Tags) {
			if !tagRe.MatchString(t) {
				return nil, fmt.Errorf("invalid tag %q", t)
			}
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
		if len(clients) == 0 && len(tags) == 0 {
			return nil, errors.New("a role limited to some clients needs at least one client or tag")
		}
		a.Clients, a.Tags = clients, tags
		out = append(out, a)
	}
	return out, nil
}

func describeAssignments(as []RoleAssignment) string {
	var parts []string
	for _, a := range as {
		scope := "all clients"
		if !a.AllClients {
			var sc []string
			if len(a.Clients) > 0 {
				sc = append(sc, fmt.Sprintf("%d client(s)", len(a.Clients)))
			}
			if len(a.Tags) > 0 {
				sc = append(sc, "tags "+strings.Join(a.Tags, ", "))
			}
			scope = strings.Join(sc, " and ")
		}
		parts = append(parts, fmt.Sprintf("%s on %s", a.RoleName, scope))
	}
	if len(parts) == 0 {
		return "no roles"
	}
	return strings.Join(parts, "; ")
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string           `json:"username"`
		Password   string           `json:"password"`
		Enabled    bool             `json:"enabled"`
		MustChange bool             `json:"must_change_password"`
		Roles      []RoleAssignment `json:"roles"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	auditTarget(r, "user "+req.Username)
	if !usernameRe.MatchString(req.Username) {
		httpError(w, http.StatusBadRequest, errors.New("username: up to 64 letters, digits, '.', '_', '@' or '-'"))
		return
	}
	if err := checkNewPassword(req.Password); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	roles, err := s.cleanAssignments(r, req.Roles)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	u := &User{Username: req.Username, Enabled: req.Enabled, MustChange: req.MustChange, Roles: roles}
	id, err := s.store.CreateUser(r.Context(), u, HashPassword(req.Password))
	if errors.Is(err, errUsernameTaken) {
		httpError(w, http.StatusConflict, err)
		return
	} else if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	auditDetail(r, "%s", describeAssignments(roles))
	s.log.Info("user created", "user", req.Username, "by", sessionUser(r).Name)
	u, err = s.store.User(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, u)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		Enabled bool             `json:"enabled"`
		Roles   []RoleAssignment `json:"roles"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	u, err := s.store.User(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	auditTarget(r, "user "+u.Username)
	if id == sessionUser(r).ID && !req.Enabled {
		httpError(w, http.StatusBadRequest, errors.New("you can't disable your own account"))
		return
	}
	roles, err := s.cleanAssignments(r, req.Roles)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpdateUser(ctx, id, req.Enabled, roles); err != nil {
		code := statusFor(err)
		if errors.Is(err, errLastAdmin) {
			code = http.StatusConflict
		}
		httpError(w, code, err)
		return
	}
	auditDetail(r, "enabled=%t, %s", req.Enabled, describeAssignments(roles))
	if u, err = s.store.User(ctx, id); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	u, err := s.store.User(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	auditTarget(r, "user "+u.Username)
	if id == sessionUser(r).ID {
		httpError(w, http.StatusBadRequest, errors.New("you can't delete your own account"))
		return
	}
	if err := s.store.DeleteUser(ctx, id); err != nil {
		code := statusFor(err)
		if errors.Is(err, errLastAdmin) {
			code = http.StatusConflict
		}
		httpError(w, code, err)
		return
	}
	s.log.Info("user deleted", "user", u.Username, "by", sessionUser(r).Name)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleResetPassword sets another user's password; by default the user
// must change it at the next sign-in.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var req struct {
		Password   string `json:"password"`
		MustChange bool   `json:"must_change_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	u, err := s.store.User(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	auditTarget(r, "user "+u.Username)
	if err := checkNewPassword(req.Password); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	keep := ""
	if id == sessionUser(r).ID {
		c, _ := r.Cookie(sessionCookie)
		keep = hashToken(c.Value)
	}
	if err := s.store.SetUserPassword(ctx, id, HashPassword(req.Password), req.MustChange, keep); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	auditDetail(r, "must change at next sign-in: %t", req.MustChange)
	s.log.Info("user password reset", "user", u.Username, "by", sessionUser(r).Name)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.Roles(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, orEmpty(rs))
}

func (s *Server) handleSaveRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []Perm `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	role := &Role{Name: strings.TrimSpace(req.Name), Description: strings.TrimSpace(req.Description), Permissions: []Perm{}}
	auditTarget(r, "role "+role.Name)
	if r.PathValue("id") != "" {
		id, err := pathID(r)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		old, err := s.store.Role(r.Context(), id)
		if err != nil {
			httpError(w, statusFor(err), err)
			return
		}
		if old.Builtin != "" {
			httpError(w, http.StatusBadRequest, errors.New("built-in roles can't be changed; create a custom role instead"))
			return
		}
		role.ID = id
	}
	if role.Name == "" || len(role.Name) > 64 {
		httpError(w, http.StatusBadRequest, errors.New("the name is required (up to 64 characters)"))
		return
	}
	for _, p := range req.Permissions {
		if _, ok := permInfo(p); !ok {
			httpError(w, http.StatusBadRequest, fmt.Errorf("unknown permission %q", p))
			return
		}
		if !slices.Contains(role.Permissions, p) {
			role.Permissions = append(role.Permissions, p)
		}
	}
	if err := s.store.SaveRole(r.Context(), role); err != nil {
		code := statusFor(err)
		if errors.Is(err, errRoleNameTaken) || errors.Is(err, errLastAdmin) {
			code = http.StatusConflict
		}
		httpError(w, code, err)
		return
	}
	auditDetail(r, "permissions: %v", role.Permissions)
	role, err := s.store.Role(r.Context(), role.ID)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, role)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	role, err := s.store.Role(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	auditTarget(r, "role "+role.Name)
	if role.Builtin != "" {
		httpError(w, http.StatusBadRequest, errors.New("built-in roles can't be deleted"))
		return
	}
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		code := statusFor(err)
		if errors.Is(err, errRoleInUse) {
			code = http.StatusConflict
		}
		httpError(w, code, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
