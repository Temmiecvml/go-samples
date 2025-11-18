package wikipedia

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		query       string
		limit       int
		response    string
		wantResults int
		wantError   bool
	}{
		{
			name:  "successful search",
			query: "golang",
			limit: 3,
			response: `{
				"query": {
					"search": [
						{"title": "Go (programming language)", "pageid": 1, "snippet": "Test"},
						{"title": "Golang", "pageid": 2, "snippet": "Test2"}
					]
				}
			}`,
			wantResults: 2,
			wantError:   false,
		},
		{
			name:        "no results",
			query:       "nonexistent",
			limit:       3,
			response:    `{"query": {"search": []}}`,
			wantResults: 0,
			wantError:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClient(server.URL, 10*time.Second)
			ctx := context.Background()
			results, err := client.Search(ctx, tt.query, tt.limit)

			if (err != nil) != tt.wantError {
				t.Errorf("Search() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if len(results) != tt.wantResults {
				t.Errorf("Expected %d results, got %d", tt.wantResults, len(results))
			}
		})
	}
}

func TestGetPageContent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query": {
				"pages": {
					"1": {
						"title": "Test Page",
						"extract": "Test content",
						"fullurl": "https://test.com"
					}
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, 10*time.Second)
	ctx := context.Background()
	content, err := client.GetPageContent(ctx, 1)

	if err != nil {
		t.Fatalf("GetPageContent() error = %v", err)
	}

	if content.Title != "Test Page" {
		t.Errorf("Expected title 'Test Page', got '%s'", content.Title)
	}

	wantContent := &PageContent{
		Title:   "Test Page",
		Extract: "Test content",
		URL:     "https://test.com",
	}

	if diff := cmp.Diff(wantContent, content); diff != "" {
		t.Errorf("PageContent mismatch (-want +got):\n%s", diff)
	}
}

func TestGetPageContentsConcurrently(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.Write([]byte(`{
			"query": {
				"pages": {
					"1": {
						"title": "Test",
						"extract": "Content",
						"fullurl": "https://test.com"
					}
				}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, 10*time.Second)
	ctx := context.Background()

	pageIDs := []int{1, 2, 3, 4, 5}
	start := time.Now()
	contents, err := client.GetPageContentsConcurrently(ctx, pageIDs, 3)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GetPageContentsConcurrently() error = %v", err)
	}

	if len(contents) != len(pageIDs) {
		t.Errorf("Expected %d contents, got %d", len(pageIDs), len(contents))
	}

	if elapsed > 100*time.Millisecond {
		t.Logf("Concurrent fetching took %v (should be faster than sequential)", elapsed)
	}
}

func TestContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte(`{"query": {"search": []}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Search(ctx, "test", 5)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

func BenchmarkSearch(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query": {"search": [{"title": "Test", "pageid": 1, "snippet": "test"}]}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, 10*time.Second)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Search(ctx, "test", 5)
	}
}
