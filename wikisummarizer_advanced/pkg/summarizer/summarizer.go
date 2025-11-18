package summarizer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
	"google.golang.org/genai"
)

// Summarizer defines a common interface for different summarization backends.
type Summarizer interface {
	Summarize(ctx context.Context, text string) (string, error)
}

//
// ─── OLLAMA SUMMARIZER ─────────────────────────────────────────────
//

type OllamaSummarizer struct {
	url        string
	model      string
	client     *http.Client
	logger     *zap.Logger
	maxRetries int
}

// NewOllamaSummarizer creates an Ollama-based summarizer.
func NewOllamaSummarizer(url, model string, timeout time.Duration, maxRetries int, logger *zap.Logger) *OllamaSummarizer {
	return &OllamaSummarizer{
		url:   url,
		model: model,
		client: &http.Client{
			Timeout: timeout,
		},
		logger:     logger,
		maxRetries: maxRetries,
	}
}

func (o *OllamaSummarizer) Summarize(ctx context.Context, text string) (string, error) {
	prompt := fmt.Sprintf("Please provide a comprehensive summary of the following text:\n\n%s", text)
	var lastErr error

	for attempt := 0; attempt <= o.maxRetries; attempt++ {
		if attempt > 0 {
			o.logger.Warn("Retrying Ollama summarization", zap.Int("attempt", attempt))
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second * time.Duration(attempt)):
			}
		}

		reqBody := map[string]interface{}{
			"model":  o.model,
			"prompt": prompt,
			"stream": false,
		}

		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			lastErr = fmt.Errorf("failed to marshal request: %w", err)
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url+"/api/generate", bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := o.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("ollama request failed: %w", err)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Response string `json:"response"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			lastErr = fmt.Errorf("failed to decode ollama response: %w", err)
			continue
		}

		return result.Response, nil
	}

	return "", fmt.Errorf("ollama summarization failed after %d attempts: %w", o.maxRetries, lastErr)
}

//
// ─── GEMINI SUMMARIZER ─────────────────────────────────────────────
//

type GeminiSummarizer struct {
	client     *genai.Client
	model      string
	logger     *zap.Logger
	maxRetries int
}

// NewGeminiSummarizer creates a Google Gemini-based summarizer using the genai SDK.
func NewGeminiSummarizer(apiKey, model string, maxRetries int, logger *zap.Logger) (*GeminiSummarizer, error) {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI, // Explicitly use Gemini backend
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	return &GeminiSummarizer{
		client:     client,
		model:      model,
		logger:     logger,
		maxRetries: maxRetries,
	}, nil
}

func (g *GeminiSummarizer) Summarize(ctx context.Context, text string) (string, error) {
	prompt := fmt.Sprintf("Please provide a comprehensive summary of the following text:\n\n%s", text)
	var lastErr error

	for attempt := 0; attempt <= g.maxRetries; attempt++ {
		if attempt > 0 {
			g.logger.Warn("Retrying Gemini summarization", zap.Int("attempt", attempt))
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second * time.Duration(attempt)):
			}
		}

		resp, err := g.client.Models.GenerateContent(
			ctx,
			g.model,
			genai.Text(prompt),
			nil,
		)
		if err != nil {
			lastErr = fmt.Errorf("gemini generate content failed: %w", err)
			continue
		}

		summary := resp.Text()
		if summary == "" {
			lastErr = fmt.Errorf("empty summary from Gemini response")
			continue
		}

		return summary, nil
	}

	return "", fmt.Errorf("gemini summarization failed after %d attempts: %w", g.maxRetries, lastErr)
}
