package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/services"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
)

// GetArticleHandler handles the fetching and summarizing of a Wikipedia article
func GetArticleHandler(w http.ResponseWriter, r *http.Request) {
	articleName := chi.URLParam(r, "name")
	if articleName == "" {
		utils.LogError("Article name is missing")
		http.Error(w, "Article name is required", http.StatusBadRequest)
		return
	}

	summary, err := services.FetchAndSummarizeArticle(articleName)
	if err != nil {
		utils.LogError("Error fetching or summarizing article: " + err.Error())
		http.Error(w, "Failed to process article", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(summary))
}
