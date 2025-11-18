package handlers

import (
	"html/template"
	"net/http"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/services"
	"go.uber.org/zap"
)

type SummaryHandler struct {
	wikiService *services.WikiService
	logger      *zap.Logger
	template    *template.Template
}

func NewSummaryHandler(wikiService *services.WikiService, logger *zap.Logger, tmpl *template.Template) *SummaryHandler {
	return &SummaryHandler{
		wikiService: wikiService,
		logger:      logger,
		template:    tmpl,
	}
}

func (h *SummaryHandler) ServeSummary(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	article, err := h.wikiService.ProcessQuery(r.Context(), query)
	if err != nil {
		h.logger.Error("Failed to process query", zap.Error(err), zap.String("query", query))
		http.Error(w, "Failed to process query", http.StatusInternalServerError)
		return
	}

	data := struct {
		Query   string
		Article interface{}
	}{
		Query:   query,
		Article: article,
	}

	if err := h.template.ExecuteTemplate(w, "summary.html", data); err != nil {
		h.logger.Error("Failed to render template", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
