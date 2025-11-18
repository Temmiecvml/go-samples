package handlers

import (
	"html/template"
	"net/http"

	"go.uber.org/zap"
)

type SearchHandler struct {
	logger   *zap.Logger
	template *template.Template
}

func NewSearchHandler(logger *zap.Logger, tmpl *template.Template) *SearchHandler {
	return &SearchHandler{
		logger:   logger,
		template: tmpl,
	}
}

func (h *SearchHandler) ServeSearch(w http.ResponseWriter, r *http.Request) {
	if err := h.template.ExecuteTemplate(w, "search.html", nil); err != nil {
		h.logger.Error("Failed to render template", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
