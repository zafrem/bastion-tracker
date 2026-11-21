package rest

// Admin-only exception management. An exception exempts one rule, for one
// tenant, from enforcement by selected modules until it expires. Tracker signs
// each change and pushes it; every create/revoke is also written to the audit
// log as an event.

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zafrem/bastion-tracker/internal/auth"
	"github.com/zafrem/bastion-tracker/internal/exceptions"
	"github.com/zafrem/bastion-tracker/internal/models"
)

type createExceptionRequest struct {
	Rule          string    `json:"rule"`
	Modules       []string  `json:"modules"`
	TenantID      string    `json:"tenant_id"`
	UserID        string    `json:"user_id"`
	Justification string    `json:"justification"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// actor names who is making the change; open-access mode has no identity.
func actor(r *http.Request) string {
	if c, ok := r.Context().Value(claimsKey).(*auth.Claims); ok && c != nil && c.UserID != "" {
		return c.UserID
	}
	return "anonymous"
}

func (h *handlers) exceptionsReady(w http.ResponseWriter) bool {
	if h.exceptions == nil || !h.exceptions.Enabled() {
		writeError(w, http.StatusServiceUnavailable,
			"exceptions are disabled: set exceptions.signing_key (see `tracker-cli exceptions keygen`)")
		return false
	}
	return true
}

func exceptionStatus(err error) int {
	if errors.Is(err, exceptions.ErrNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, exceptions.ErrDisabled) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// audit records the change in Tracker's own event log.
func (h *handlers) auditException(kind string, e exceptions.Exception, by string) {
	h.proc.Process(models.BastionEvent{
		EventID:   "exc-" + kind + "-" + e.ID + "-" + time.Now().UTC().Format("150405.000000"),
		Module:    "tracker",
		EventType: "exception_" + kind,
		Severity:  "warning",
		Category:  "audit",
		Timestamp: time.Now().UTC(),
		TenantID:  e.TenantID,
		UserID:    by,
		Status:    "passed",
		Data: map[string]any{
			"exception_id": e.ID, "rule": e.Rule, "modules": e.Modules,
			"scope_user": e.UserID, "expires_at": e.ExpiresAt, "justification": e.Justification,
		},
	})
}

// ListExceptions returns every exception plus the public key modules verify with.
func (h *handlers) ListExceptions(w http.ResponseWriter, r *http.Request) {
	if !h.exceptionsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_key": h.exceptions.PublicKey(),
		"exceptions": h.exceptions.List(),
	})
}

// CreateException issues a new exception.
func (h *handlers) CreateException(w http.ResponseWriter, r *http.Request) {
	if !h.exceptionsReady(w) {
		return
	}
	var req createExceptionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	by := actor(r)
	e, err := h.exceptions.Create(exceptions.Exception{
		Rule: req.Rule, Modules: req.Modules, TenantID: req.TenantID, UserID: req.UserID,
		Justification: req.Justification, ExpiresAt: req.ExpiresAt,
	}, by)
	if err != nil {
		writeError(w, exceptionStatus(err), err.Error())
		return
	}
	h.auditException("created", e, by)
	writeJSON(w, http.StatusCreated, e)
}

// RevokeException withdraws an exception everywhere.
func (h *handlers) RevokeException(w http.ResponseWriter, r *http.Request) {
	if !h.exceptionsReady(w) {
		return
	}
	by := actor(r)
	e, err := h.exceptions.Revoke(chi.URLParam(r, "id"), by)
	if err != nil {
		writeError(w, exceptionStatus(err), err.Error())
		return
	}
	h.auditException("revoked", e, by)
	writeJSON(w, http.StatusOK, e)
}

// ExportExceptions returns a signed snapshot for modules with no connection to
// Tracker: save it as the module's exceptions file.
func (h *handlers) ExportExceptions(w http.ResponseWriter, r *http.Request) {
	if !h.exceptionsReady(w) {
		return
	}
	env, err := h.exceptions.Export()
	if err != nil {
		writeError(w, exceptionStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, env)
}
