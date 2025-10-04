package handlers

import (
	"net/http"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
)

// UserHandler handles user-related routes
func UserHandler(w http.ResponseWriter, r *http.Request) {
	logger := utils.GetLogger("handlers.user_handler")
	logger.Info("UserHandler invoked")
	w.Write([]byte("User endpoint"))
}
