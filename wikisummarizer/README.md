# Wikipedia Article Summarizer API

## Features
- Fetch the most relevant Wikipedia article based on a user-provided name.
- Summarize the article using Ollama.
- Store the summarized article in an SQLite database.
- Retrieve stored articles.
- Delete articles by ID.

## Endpoints

### Public Routes
- **GET /api/articles/{name}**
  - Fetch and summarize a Wikipedia article by name.
  - **Business Logic**: For each article, retrieve the content from Wikipedia, summarize it using Ollama, and then return the summarized details.
  - **Path Parameter**: `name` (string) - The name of the article to fetch.
  - **Response**: Summarized content of the article.

### Private Routes (Future-proofed for authentication)
- **GET /api/admin/articles**
  - Retrieve metadata/details not content of all stored articles.

  - **Response**: List of articles with their details.

- **DELETE /api/admin/articles/{id}**
  - Delete an article by its ID.
  - **Path Parameter**: `id` (integer) - The ID of the article to delete.

## Database Tables

### Articles Table
| Column      | Type      | Description                       |
|-------------|-----------|-----------------------------------|
| id          | INTEGER   | Primary key, auto-incremented.    |
| name        | TEXT      | Name of the Wikipedia article.    |
| summary     | TEXT      | Summarized content of the article.|
| created_at  | DATETIME  | Timestamp of when the article was added.|

## Models

### Article Model
```go
// Article represents a summarized Wikipedia article.
type Article struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Summary   string `json:"summary"`
	CreatedAt string `json:"created_at"`
}
```