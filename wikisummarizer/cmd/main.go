package main

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/config"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/routes"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/server"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application failed to start: %v", err)
	}
}

func run() error {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		return err
	}

	// Load application config
	cfg := config.New()

	// Initialize logger
	if err := utils.InitLogger(cfg.LogLevel); err != nil {
		return err
	}
	defer utils.SyncLogger()
	utils.LogDebug("Logger initialized successfully")

	// Start the server
	utils.LogInfo("Starting server on port " + cfg.Port)
	r := routes.NewRouter()
	server.StartServer(":"+cfg.Port, r)

	return nil
}
