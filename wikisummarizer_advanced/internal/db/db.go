package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

type Database struct {
	DB     *sql.DB
	logger *zap.Logger
}

func NewDatabase(dbPath string, maxOpenConns, maxIdleConns int, connMaxLifetime time.Duration, logger *zap.Logger) (*Database, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{
		DB:     db,
		logger: logger,
	}

	if err := database.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	if err := database.createDefaultAdmin(); err != nil {
		logger.Warn("Failed to create default admin", zap.Error(err))
	}

	return database, nil
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS articles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			query TEXT NOT NULL,
			summary TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			article_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			url TEXT NOT NULL,
			position INTEGER NOT NULL,
			FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			summarizer_type TEXT NOT NULL DEFAULT 'ollama',
			ollama_url TEXT NOT NULL DEFAULT 'http://localhost:11434',
			ollama_model TEXT NOT NULL DEFAULT 'llama2',
			gemini_api_key TEXT DEFAULT '',
			gemini_model TEXT NOT NULL DEFAULT 'gemini-pro'
		)`,
		`INSERT OR IGNORE INTO settings (id, summarizer_type) VALUES (1, 'ollama')`,
	}

	for _, query := range queries {
		if _, err := d.DB.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

func (d *Database) createDefaultAdmin() error {
	var count int
	err := d.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	hashedPassword := "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
	_, err = d.DB.Exec(
		"INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
		"admin", hashedPassword, "admin@wikisummarizer.com", "admin",
	)

	return err
}

func (d *Database) Close() error {
	return d.DB.Close()
}
