package routes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
)

func NewRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Home routes
	r.Route("/", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte("Hello World!")) // Handle error
			if err != nil {
				utils.LogError("Error writing response: " + err.Error())
			}
		})
	})

	return r
}
