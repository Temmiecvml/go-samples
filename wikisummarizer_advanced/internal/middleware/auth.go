package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/auth"
	"go.uber.org/zap"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"

func AuthMiddleware(jwtService *auth.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn("Missing authorization header")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				logger.Warn("Invalid authorization header format")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			token := parts[1]
			claims, err := jwtService.ValidateToken(token)
			if err != nil {
				logger.Warn("Invalid token", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AdminMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*auth.Claims)
			if !ok {
				logger.Warn("No claims in context")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if claims.Role != "admin" {
				logger.Warn("User is not admin", zap.String("username", claims.Username))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
