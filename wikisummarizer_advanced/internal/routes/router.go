package routes

import (
	"html/template"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/auth"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/db"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/handlers"
	mw "github.com/temmiecvml/go-samples/wikisummarizer/internal/middleware"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/services"
	"go.uber.org/zap"
)

func NewRouter(
	wikiService *services.WikiService,
	database *db.Database,
	jwtService *auth.JWTService,
	logger *zap.Logger,
) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(mw.LoggingMiddleware(logger))

	tmpl := template.Must(template.ParseGlob("web/templates/*.html"))

	searchHandler := handlers.NewSearchHandler(logger, tmpl)
	summaryHandler := handlers.NewSummaryHandler(wikiService, logger, tmpl)
	authHandler := handlers.NewAuthHandler(database, jwtService, logger, tmpl)
	adminHandler := handlers.NewAdminHandler(database, logger, tmpl)

	r.Get("/", searchHandler.ServeSearch)
	r.Get("/summary", summaryHandler.ServeSummary)
	r.Get("/admin/login", authHandler.ServeLoginPage)

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", authHandler.Login)

		r.Route("/admin", func(r chi.Router) {
			r.Use(mw.AuthMiddleware(jwtService, logger))
			r.Use(mw.AdminMiddleware(logger))

			r.Get("/articles", adminHandler.GetArticles)
			r.Delete("/articles/{id}", adminHandler.DeleteArticle)

			r.Get("/users", adminHandler.GetUsers)
			r.Post("/users", adminHandler.CreateUser)
			r.Put("/users/{id}", adminHandler.UpdateUser)
			r.Delete("/users/{id}", adminHandler.DeleteUser)

			r.Get("/settings", adminHandler.GetSettings)
			r.Put("/settings", adminHandler.UpdateSettings)
		})
	})

	r.Get("/admin", adminHandler.ServeAdminPanel)

	return r
}
