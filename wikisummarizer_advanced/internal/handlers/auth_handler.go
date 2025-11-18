package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/auth"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/db"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/models"
	"go.uber.org/zap"
)

type AuthHandler struct {
	db         *db.Database
	jwtService *auth.JWTService
	logger     *zap.Logger
	template   *template.Template
}

func NewAuthHandler(database *db.Database, jwtService *auth.JWTService, logger *zap.Logger, tmpl *template.Template) *AuthHandler {
	return &AuthHandler{
		db:         database,
		jwtService: jwtService,
		logger:     logger,
		template:   tmpl,
	}
}

func (h *AuthHandler) ServeLoginPage(w http.ResponseWriter, r *http.Request) {
	if err := h.template.ExecuteTemplate(w, "login.html", nil); err != nil {
		h.logger.Error("Failed to render template", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		h.logger.Error("Database error", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil || !auth.VerifyPassword(user.Password, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := h.jwtService.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		h.logger.Error("Failed to generate token", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := models.LoginResponse{
		Token: token,
		User:  *user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
