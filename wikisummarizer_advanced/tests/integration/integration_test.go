//go:build integration
// +build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/auth"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/config"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/db"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/routes"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/services"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/summarizer"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/utils"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/wikipedia"
)

func setupIntegrationTest(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	os.Setenv("DATABASE_PATH", ":memory:")
	t.Cleanup(func() {
		os.Unsetenv("DATABASE_PATH")
	})

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}

	logger, _ := utils.InitLogger(cfg.Logging)

	database, err := db.NewDatabase(
		cfg.Database.Path,
		cfg.Database.MaxOpenConns,
		cfg.Database.MaxIdleConns,
		cfg.Database.ConnMaxLifetime,
		logger,
	)
	if err != nil {
		t.Fatal(err)
	}

	jwtService := auth.NewJWTService(cfg.JWT.Secret, cfg.JWT.ExpirationHours)
	wikiClient := wikipedia.NewClient(cfg.Wikipedia.APIURL, cfg.Wikipedia.Timeout)
	sum := summarizer.NewOllamaSummarizer(
		"http://localhost:11434",
		"llama2",
		cfg.Summarizer.Timeout,
		cfg.Summarizer.MaxRetries,
		logger,
	)

	wikiService := services.NewWikiService(
		wikiClient,
		sum,
		database,
		5,
		3,
		logger,
	)

	router := routes.NewRouter(wikiService, database, jwtService, logger)

	server := httptest.NewServer(router)

	cleanup := func() {
		server.Close()
		database.Close()
	}

	return server, cleanup
}

func TestFullWorkflow(t *testing.T) {
	server, cleanup := setupIntegrationTest(t)
	defer cleanup()

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
