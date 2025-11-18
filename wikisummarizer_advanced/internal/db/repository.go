package db

import (
	"context"
	"database/sql"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/models"
)

func (d *Database) SaveArticle(ctx context.Context, article *models.Article) error {
	tx, err := d.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"INSERT INTO articles (name, query, summary) VALUES (?, ?, ?)",
		article.Name, article.Query, article.Summary,
	)
	if err != nil {
		return err
	}

	articleID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	for i, source := range article.Sources {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO sources (article_id, title, url, position) VALUES (?, ?, ?, ?)",
			articleID, source.Title, source.URL, i,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (d *Database) GetAllArticles(ctx context.Context) ([]models.Article, error) {
	rows, err := d.DB.QueryContext(ctx, "SELECT id, name, query, summary, created_at FROM articles ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var articles []models.Article
	for rows.Next() {
		var article models.Article
		err := rows.Scan(&article.ID, &article.Name, &article.Query, &article.Summary, &article.CreatedAt)
		if err != nil {
			return nil, err
		}
		articles = append(articles, article)
	}

	return articles, nil
}

func (d *Database) DeleteArticle(ctx context.Context, id int) error {
	_, err := d.DB.ExecContext(ctx, "DELETE FROM articles WHERE id = ?", id)
	return err
}

func (d *Database) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := d.DB.QueryRowContext(ctx,
		"SELECT id, username, password, email, role, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (d *Database) GetAllUsers(ctx context.Context) ([]models.User, error) {
	rows, err := d.DB.QueryContext(ctx, "SELECT id, username, email, role, created_at, updated_at FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func (d *Database) CreateUser(ctx context.Context, user *models.User) error {
	_, err := d.DB.ExecContext(ctx,
		"INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
		user.Username, user.Password, user.Email, user.Role,
	)
	return err
}

func (d *Database) UpdateUser(ctx context.Context, user *models.User) error {
	_, err := d.DB.ExecContext(ctx,
		"UPDATE users SET email = ?, role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		user.Email, user.Role, user.ID,
	)
	return err
}

func (d *Database) DeleteUser(ctx context.Context, id int) error {
	_, err := d.DB.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	return err
}

func (d *Database) GetSettings(ctx context.Context) (*models.Settings, error) {
	var settings models.Settings
	err := d.DB.QueryRowContext(ctx,
		"SELECT id, summarizer_type, ollama_url, ollama_model, gemini_api_key, gemini_model FROM settings WHERE id = 1",
	).Scan(&settings.ID, &settings.SummarizerType, &settings.OllamaURL, &settings.OllamaModel, &settings.GeminiAPIKey, &settings.GeminiModel)

	if err != nil {
		return nil, err
	}

	return &settings, nil
}

func (d *Database) UpdateSettings(ctx context.Context, settings *models.Settings) error {
	_, err := d.DB.ExecContext(ctx,
		"UPDATE settings SET summarizer_type = ?, ollama_url = ?, ollama_model = ?, gemini_api_key = ?, gemini_model = ? WHERE id = 1",
		settings.SummarizerType, settings.OllamaURL, settings.OllamaModel, settings.GeminiAPIKey, settings.GeminiModel,
	)
	return err
}
