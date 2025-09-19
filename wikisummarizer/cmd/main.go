package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/routes"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/utils"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/server"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize logger
	utils.InitLogger()
	utils.LogInfo("Logger initialized successfully")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000" // Default port
	}
	utils.LogInfo("Starting server on port " + port)
	r := routes.NewRouter()
	server.StartServer(":"+port, r)
}
