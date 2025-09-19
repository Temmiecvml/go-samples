package server
package routes
import (
	"log"
	"net/http"
)

func StartServer(addr string, handler http.Handler) {
	log.Printf("Listening on port %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	return r
}
