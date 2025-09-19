package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

var DB *sql.DB

// InitDB initializes the SQLite database connection
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./articles.db")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	createTableQuery := `CREATE TABLE IF NOT EXISTS articles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		summary TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err = DB.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

// InsertArticle inserts a new article into the database
func InsertArticle(name, summary string) error {
	_, err := DB.Exec("INSERT INTO articles (name, summary) VALUES (?, ?)", name, summary)
	return err
}

// FetchArticles retrieves all articles from the database
func FetchArticles() ([]map[string]interface{}, error) {
	rows, err := DB.Query("SELECT id, name, summary, created_at FROM articles")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var articles []map[string]interface{}
	for rows.Next() {
		var id int
		var name, summary, createdAt string
		if err := rows.Scan(&id, &name, &summary, &createdAt); err != nil {
			return nil, err
		}
		articles = append(articles, map[string]interface{}{
			"id":        id,
			"name":      name,
			"summary":   summary,
			"created_at": createdAt,
		})
	}
	return articles, nil
}

// DeleteArticle deletes an article by ID
func DeleteArticle(id int) error {
	_, err := DB.Exec("DELETE FROM articles WHERE id = ?", id)
	return err
}