package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Server     ServerConfig
	Logging    LoggingConfig
	Database   DatabaseConfig
	Summarizer SummarizerConfig
	JWT        JWTConfig
	Wikipedia  WikipediaConfig
}

type ServerConfig struct {
	Port            string
	Host            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type LoggingConfig struct {
	Level       zapcore.Level
	Development bool
	Encoding    string
	OutputPaths []string
}

type DatabaseConfig struct {
	Driver          string
	Path            string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type SummarizerConfig struct {
	Provider     string
	OllamaURL    string
	OllamaModel  string
	GeminiAPIKey string
	GeminiModel  string
	Timeout      time.Duration
	MaxRetries   int
}

type JWTConfig struct {
	Secret          string
	ExpirationHours int
}

type WikipediaConfig struct {
	APIURL            string
	MaxArticles       int
	Timeout           time.Duration
	ConcurrentFetches int
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")

	v.AutomaticEnv()

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	}
	bindEnvVariables(v)

	cfg := &Config{}

	cfg.Server = ServerConfig{
		Port:            v.GetString("server.port"),
		Host:            v.GetString("server.host"),
		ReadTimeout:     v.GetDuration("server.read_timeout"),
		WriteTimeout:    v.GetDuration("server.write_timeout"),
		ShutdownTimeout: v.GetDuration("server.shutdown_timeout"),
	}

	logLevel, err := zapcore.ParseLevel(v.GetString("logging.level"))
	if err != nil {
		logLevel = zapcore.InfoLevel
	}
	cfg.Logging = LoggingConfig{
		Level:       logLevel,
		Development: v.GetBool("logging.development"),
		Encoding:    v.GetString("logging.encoding"),
		OutputPaths: v.GetStringSlice("logging.output_paths"),
	}

	cfg.Database = DatabaseConfig{
		Driver:          v.GetString("database.driver"),
		Path:            v.GetString("database.path"),
		MaxOpenConns:    v.GetInt("database.max_open_conns"),
		MaxIdleConns:    v.GetInt("database.max_idle_conns"),
		ConnMaxLifetime: v.GetDuration("database.conn_max_lifetime"),
	}

	cfg.Summarizer = SummarizerConfig{
		Provider:     v.GetString("summarizer.provider"),
		OllamaURL:    v.GetString("summarizer.ollama_url"),
		OllamaModel:  v.GetString("summarizer.ollama_model"),
		GeminiAPIKey: v.GetString("summarizer.gemini_api_key"),
		GeminiModel:  v.GetString("summarizer.gemini_model"),
		Timeout:      v.GetDuration("summarizer.timeout"),
		MaxRetries:   v.GetInt("summarizer.max_retries"),
	}

	cfg.JWT = JWTConfig{
		Secret:          v.GetString("jwt.secret"),
		ExpirationHours: v.GetInt("jwt.expiration_hours"),
	}

	cfg.Wikipedia = WikipediaConfig{
		APIURL:            v.GetString("wikipedia.api_url"),
		MaxArticles:       v.GetInt("wikipedia.max_articles"),
		Timeout:           v.GetDuration("wikipedia.timeout"),
		ConcurrentFetches: v.GetInt("wikipedia.concurrent_fetches"),
	}

	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", "3000")
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.read_timeout", "15s")
	v.SetDefault("server.write_timeout", "15s")
	v.SetDefault("server.shutdown_timeout", "10s")

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.development", false)
	v.SetDefault("logging.encoding", "json")
	v.SetDefault("logging.output_paths", []string{"stdout", "./logs/app.log"})

	v.SetDefault("database.driver", "sqlite3")
	v.SetDefault("database.path", "./data/wikisummarizer.db")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")

	v.SetDefault("summarizer.provider", "ollama")
	v.SetDefault("summarizer.ollama_url", "http://localhost:11434")
	v.SetDefault("summarizer.ollama_model", "llama2")
	v.SetDefault("summarizer.gemini_model", "gemini-pro")
	v.SetDefault("summarizer.timeout", "60s")
	v.SetDefault("summarizer.max_retries", 3)

	v.SetDefault("jwt.secret", "change-this-secret")
	v.SetDefault("jwt.expiration_hours", 24)

	v.SetDefault("wikipedia.api_url", "https://en.wikipedia.org/w/api.php")
	v.SetDefault("wikipedia.max_articles", 5)
	v.SetDefault("wikipedia.timeout", "30s")
	v.SetDefault("wikipedia.concurrent_fetches", 3)
}

func bindEnvVariables(v *viper.Viper) {
	if port := os.Getenv("PORT"); port != "" {
		v.Set("server.port", port)
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		v.Set("logging.level", logLevel)
	}
	if dbPath := os.Getenv("DATABASE_PATH"); dbPath != "" {
		v.Set("database.path", dbPath)
	}
	if provider := os.Getenv("SUMMARIZER_PROVIDER"); provider != "" {
		v.Set("summarizer.provider", provider)
	}
	if ollamaURL := os.Getenv("OLLAMA_URL"); ollamaURL != "" {
		v.Set("summarizer.ollama_url", ollamaURL)
	}
	if geminiKey := os.Getenv("GEMINI_API_KEY"); geminiKey != "" {
		v.Set("summarizer.gemini_api_key", geminiKey)
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		v.Set("jwt.secret", jwtSecret)
	}
}
