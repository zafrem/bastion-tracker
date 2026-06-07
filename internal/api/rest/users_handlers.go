package rest

// Admin-only user-management handlers. Users live in an in-memory store seeded
// from config (see internal/users); all routes here are wired behind
// adminOrOpen() in server.go.

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bastion/tracker/internal/models"
	"github.com/bastion/tracker/internal/users"
)

// userErrorStatus maps a users package error to an HTTP status code.
func userErrorStatus(err error) int {
	switch {
	case errors.Is(err, users.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, users.ErrExists):
		return http.StatusConflict
	case errors.Is(err, users.ErrLastAdmin):
		return http.StatusConflict
	case errors.Is(err, users.ErrInvalidRole),
		errors.Is(err, users.ErrEmptyName),
		errors.Is(err, users.ErrEmptyPassword):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// ListUsers returns all users (password-free).
func (h *handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.users.List())
}

// GetUser returns a single user by name.
func (h *handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	u, err := h.users.Get(name)
	if err != nil {
		writeError(w, userErrorStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// CreateUser adds a new user.
func (h *handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := h.users.Create(req.Name, req.Password, req.Role)
	if err != nil {
		writeError(w, userErrorStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// UpdateUser changes a user's role and/or password. Empty fields are ignored.
func (h *handlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req models.UpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" && req.Password == "" {
		writeError(w, http.StatusBadRequest, "nothing to update: provide role and/or password")
		return
	}
	if req.Password != "" {
		if err := h.users.SetPassword(name, req.Password); err != nil {
			writeError(w, userErrorStatus(err), err.Error())
			return
		}
	}
	if req.Role != "" {
		if _, err := h.users.UpdateRole(name, req.Role); err != nil {
			writeError(w, userErrorStatus(err), err.Error())
			return
		}
	}
	u, err := h.users.Get(name)
	if err != nil {
		writeError(w, userErrorStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// DeleteUser removes a user.
func (h *handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.users.Delete(name); err != nil {
		writeError(w, userErrorStatus(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
