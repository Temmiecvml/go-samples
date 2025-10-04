package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/config"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/routes"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/server"
	"go.uber.org/zap"
)

var logger *zap.Logger

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application failed to start: %v", err)
	}
}

func run() error {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Load application config
	cfg := config.New()

	// Initialize logger
	var err error
	logger, err = utils.InitLoggerRotating(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Sync()
	logger.Info("Logger initialized successfully")

	// Start the server
	logger.Info("Starting server on port " + cfg.Port)
	r := routes.NewRouter()
	server.StartServer(":"+cfg.Port, r)

	return nil
}
