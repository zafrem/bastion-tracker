package rest

import (
	"context"
	"net/http"
	"strings"

	"github.com/bastion/tracker/internal/auth"
)

type contextKey string

const claimsKey contextKey = "claims"

// jwtMiddleware validates the Bearer token and injects Claims into the request context.
func jwtMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(hdr, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing Bearer token")
				return
			}
			claims, err := auth.ValidateToken(strings.TrimPrefix(hdr, "Bearer "), secret)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireMinRole rejects requests whose role level is below the minimum required.
func requireMinRole(minRole string) func(http.Handler) http.Handler {
	min := auth.RoleLevel(minRole)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
			if !ok || claims == nil {
				writeError(w, http.StatusForbidden, "no auth context")
				return
			}
			if auth.RoleLevel(claims.Role) < min {
				writeError(w, http.StatusForbidden,
					"role '"+claims.Role+"' is insufficient; need at least '"+minRole+"'")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
