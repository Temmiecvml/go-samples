package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/auth"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/config"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/db"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/routes"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/services"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/summarizer"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/utils"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/wikipedia"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}

func run() error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger, err := utils.InitLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("Starting WikiSummarizer application")

	database, err := db.NewDatabase(
		cfg.Database.Path,
		cfg.Database.MaxOpenConns,
		cfg.Database.MaxIdleConns,
		cfg.Database.ConnMaxLifetime,
		logger,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer database.Close()

	jwtService := auth.NewJWTService(cfg.JWT.Secret, cfg.JWT.ExpirationHours)

	wikiClient := wikipedia.NewClient(cfg.Wikipedia.APIURL, cfg.Wikipedia.Timeout)

	settings, err := database.GetSettings(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get settings: %w", err)
	}

	var sum summarizer.Summarizer
	if settings.SummarizerType == "gemini" && settings.GeminiAPIKey != "" {
		sum, err = summarizer.NewGeminiSummarizer(
			settings.GeminiAPIKey,
			settings.GeminiModel,
			cfg.Summarizer.MaxRetries,
			logger,
		)
		if err != nil {
			logger.Warn("Failed to initialize Gemini, falling back to Ollama", zap.Error(err))
			sum = summarizer.NewOllamaSummarizer(
				settings.OllamaURL,
				settings.OllamaModel,
				cfg.Summarizer.Timeout,
				cfg.Summarizer.MaxRetries,
				logger,
			)
		}
	} else {
		sum = summarizer.NewOllamaSummarizer(
			settings.OllamaURL,
			settings.OllamaModel,
			cfg.Summarizer.Timeout,
			cfg.Summarizer.MaxRetries,
			logger,
		)
	}

	wikiService := services.NewWikiService(
		wikiClient,
		sum,
		database,
		cfg.Wikipedia.MaxArticles,
		cfg.Wikipedia.ConcurrentFetches,
		logger,
	)

	router := routes.NewRouter(wikiService, database, jwtService, logger)

	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		logger.Info("Server starting", zap.String("port", cfg.Server.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	logger.Info("Server exited properly")
	return nil
}
