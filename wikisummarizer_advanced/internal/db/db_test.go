package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/models"
	"go.uber.org/zap"
)

func setupTestDB(t *testing.T) (*Database, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	logger, _ := zap.NewDevelopment()
	db, err := NewDatabase(dbPath, 10, 5, 5*time.Minute, logger)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

func TestNewDatabase(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	if db == nil {
		t.Fatal("Expected non-nil database")
	}

	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='articles'").Scan(&count)
	if err != nil || count == 0 {
		t.Error("Articles table not created")
	}
}

func TestSaveAndGetArticle(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	article := &models.Article{
		Name:    "Test",
		Query:   "test query",
		Summary: "test summary",
		Sources: []models.Source{
			{Title: "Source 1", URL: "http://example.com", Position: 0},
		},
	}

	err := db.SaveArticle(ctx, article)
	if err != nil {
		t.Fatalf("Failed to save article: %v", err)
	}

	articles, err := db.GetAllArticles(ctx)
	if err != nil {
		t.Fatalf("Failed to get articles: %v", err)
	}

	if len(articles) != 1 {
		t.Errorf("Expected 1 article, got %d", len(articles))
	}

	if diff := cmp.Diff(article.Name, articles[0].Name); diff != "" {
		t.Errorf("Article name mismatch (-want +got):\n%s", diff)
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			article := &models.Article{
				Name:    "Test",
				Query:   "Query",
				Summary: "Summary",
			}
			err := db.SaveArticle(ctx, article)
			if err != nil {
				t.Errorf("Concurrent insert failed: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestContextCancellation(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	article := &models.Article{
		Name:    "Test",
		Query:   "test",
		Summary: "summary",
	}

	err := db.SaveArticle(ctx, article)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

func BenchmarkSaveArticle(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	logger, _ := zap.NewDevelopment()
	db, _ := NewDatabase(dbPath, 10, 5, 5*time.Minute, logger)
	defer db.Close()

	ctx := context.Background()
	article := &models.Article{
		Name:    "Bench",
		Query:   "bench",
		Summary: "summary",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.SaveArticle(ctx, article)
	}
}

func FuzzArticleName(f *testing.F) {
	tmpDir := f.TempDir()
	dbPath := filepath.Join(tmpDir, "fuzz.db")
	logger, _ := zap.NewDevelopment()
	db, _ := NewDatabase(dbPath, 10, 5, 5*time.Minute, logger)
	defer db.Close()

	f.Add("Test Article")
	f.Add("Special chars: !@#$%")
	f.Add("Unicode: 你好")

	f.Fuzz(func(t *testing.T, name string) {
		ctx := context.Background()
		article := &models.Article{
			Name:    name,
			Query:   "test",
			Summary: "test",
		}
		_ = db.SaveArticle(ctx, article)
	})
}
