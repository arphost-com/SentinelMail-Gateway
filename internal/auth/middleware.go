package auth

import (
	"context"
	"net/http"
)

type ctxKey struct{}

var identityKey ctxKey

func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func IdentityFrom(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok
}

// Middleware extracts the session cookie, resolves it, and injects an Identity
// into the request context. Unauthenticated requests get a 401.
func Middleware(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			ident, err := store.Lookup(r.Context(), cookie.Value)
			if err != nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), ident)))
		})
	}
}

// RequireRole enforces that the authenticated user has one of the listed roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allow := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allow[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident, ok := IdentityFrom(r.Context())
			if !ok {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if _, allowed := allow[ident.Role]; !allowed {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
