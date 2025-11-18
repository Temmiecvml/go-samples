package models

import "time"

type Article struct {
	ID        int       `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Query     string    `json:"query" db:"query"`
	Summary   string    `json:"summary" db:"summary"`
	Sources   []Source  `json:"sources"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Source struct {
	ID        int    `json:"id" db:"id"`
	ArticleID int    `json:"article_id" db:"article_id"`
	Title     string `json:"title" db:"title"`
	URL       string `json:"url" db:"url"`
	Position  int    `json:"position" db:"position"`
}
