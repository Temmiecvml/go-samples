package wikipedia

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Client struct {
	apiURL     string
	httpClient *http.Client
}

type SearchResult struct {
	Title   string
	PageID  int
	Snippet string
	URL     string
}

type PageContent struct {
	Title   string
	Extract string
	URL     string
}

func NewClient(apiURL string, timeout time.Duration) *Client {
	return &Client{
		apiURL: apiURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	params := url.Values{}
	params.Set("action", "query")
	params.Set("list", "search")
	params.Set("srsearch", query)
	params.Set("srlimit", fmt.Sprintf("%d", limit))
	params.Set("format", "json")

	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Query struct {
			Search []struct {
				Title   string `json:"title"`
				PageID  int    `json:"pageid"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	var results []SearchResult
	for _, item := range result.Query.Search {
		results = append(results, SearchResult{
			Title:   item.Title,
			PageID:  item.PageID,
			Snippet: item.Snippet,
			URL:     fmt.Sprintf("https://en.wikipedia.org/wiki/%s", url.PathEscape(item.Title)),
		})
	}

	return results, nil
}

func (c *Client) GetPageContent(ctx context.Context, pageID int) (*PageContent, error) {
	params := url.Values{}
	params.Set("action", "query")
	params.Set("pageids", fmt.Sprintf("%d", pageID))
	params.Set("prop", "extracts|info")
	params.Set("exintro", "true")
	params.Set("explaintext", "true")
	params.Set("inprop", "url")
	params.Set("format", "json")

	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("page content request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Query struct {
			Pages map[string]struct {
				Title   string `json:"title"`
				Extract string `json:"extract"`
				FullURL string `json:"fullurl"`
			} `json:"pages"`
		} `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode page content: %w", err)
	}

	for _, page := range result.Query.Pages {
		return &PageContent{
			Title:   page.Title,
			Extract: page.Extract,
			URL:     page.FullURL,
		}, nil
	}

	return nil, fmt.Errorf("page not found")
}

// GetPageContentsConcurrently fetches multiple pages concurrently
func (c *Client) GetPageContentsConcurrently(ctx context.Context, pageIDs []int, concurrency int) ([]*PageContent, error) {
	results := make([]*PageContent, len(pageIDs))
	errs := make([]error, len(pageIDs))

	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, pageID := range pageIDs {
		wg.Add(1)
		go func(idx, pid int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errs[idx] = ctx.Err()
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}

			content, err := c.GetPageContent(ctx, pid)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = content
		}(i, pageID)
	}

	wg.Wait()

	// Check for errors
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}
