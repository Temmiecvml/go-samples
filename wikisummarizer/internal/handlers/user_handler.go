package handlers

import (
	"net/http"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
)

// UserHandler handles user-related routes
func UserHandler(w http.ResponseWriter, r *http.Request) {
	utils.LogInfo("UserHandler invoked")
	w.Write([]byte("User endpoint"))
}
