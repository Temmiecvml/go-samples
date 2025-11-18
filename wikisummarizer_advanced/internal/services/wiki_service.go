package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/db"
	"github.com/temmiecvml/go-samples/wikisummarizer/internal/models"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/summarizer"
	"github.com/temmiecvml/go-samples/wikisummarizer/pkg/wikipedia"
	"go.uber.org/zap"
)

type WikiService struct {
	wikiClient        *wikipedia.Client
	summarizer        summarizer.Summarizer
	db                *db.Database
	logger            *zap.Logger
	maxArticles       int
	concurrentFetches int
}

func NewWikiService(
	wikiClient *wikipedia.Client,
	sum summarizer.Summarizer,
	database *db.Database,
	maxArticles int,
	concurrentFetches int,
	logger *zap.Logger,
) *WikiService {
	return &WikiService{
		wikiClient:        wikiClient,
		summarizer:        sum,
		db:                database,
		logger:            logger,
		maxArticles:       maxArticles,
		concurrentFetches: concurrentFetches,
	}
}

func (w *WikiService) ProcessQuery(ctx context.Context, query string) (*models.Article, error) {
	w.logger.Info("Processing query", zap.String("query", query))

	searchResults, err := w.wikiClient.Search(ctx, query, w.maxArticles)
	if err != nil {
		return nil, fmt.Errorf("failed to search Wikipedia: %w", err)
	}

	if len(searchResults) == 0 {
		return nil, fmt.Errorf("no articles found for query: %s", query)
	}

	// Extract page IDs
	pageIDs := make([]int, len(searchResults))
	for i, result := range searchResults {
		pageIDs[i] = result.PageID
	}

	// Fetch pages concurrently
	contents, err := w.wikiClient.GetPageContentsConcurrently(ctx, pageIDs, w.concurrentFetches)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page contents: %w", err)
	}

	// Build content and sources
	var contentBuilder strings.Builder
	var sources []models.Source

	for i, content := range contents {
		if content != nil {
			contentBuilder.WriteString(fmt.Sprintf("## %s\n%s\n\n", content.Title, content.Extract))
			sources = append(sources, models.Source{
				Title:    content.Title,
				URL:      content.URL,
				Position: i,
			})
		}
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("failed to fetch any article content")
	}

	// Summarize
	summary, err := w.summarizer.Summarize(ctx, contentBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("failed to summarize content: %w", err)
	}

	article := &models.Article{
		Name:    searchResults[0].Title,
		Query:   query,
		Summary: summary,
		Sources: sources,
	}

	// Save to database
	if err := w.db.SaveArticle(ctx, article); err != nil {
		w.logger.Error("Failed to save article", zap.Error(err))
	}

	return article, nil
}
