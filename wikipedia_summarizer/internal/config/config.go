package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Server     ServerConfig
	Logging    LoggingConfig
	Database   DatabaseConfig
	Summarizer SummarizerConfig
	JWT        JWTConfig
}

type ServerConfig struct {
	Port string
	Host string
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
	Provider   string
	URL        string
	Model      string
	APIKey     string
	MaxRetries int
}

type JWTConfig struct {
	Secret          string
	ExpirationHours int
}

func New() (*Config, error) {

	loadEnv()

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	// Set up environment variable handling
	v.AutomaticEnv()
	// Use underscores in environment variable names
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	}

	cfg := createConfig(v)

	return cfg, nil
}

func loadEnv() {
	// Try multiple .env locations in order of precedence
	envPaths := []string{
		".env",                   // Project root (most common)
		"./internal/config/.env", // Config package directory
	}

	var envLoaded bool
	for _, envPath := range envPaths {
		if err := godotenv.Load(envPath); err == nil {
			envLoaded = true
			break
		}
	}

	if !envLoaded {
		// Fallback to default godotenv behavior (current directory)
		if err := godotenv.Load(); err != nil {
			fmt.Printf("Warning: No .env file found in common locations\n")
		}
	}

}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", "3000")
	v.SetDefault("server.host", "localhost")

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
	v.SetDefault("summarizer.url", "http://localhost:11434")
	v.SetDefault("summarizer.model", "llama2")
	v.SetDefault("summarizer.api_key", "")
	v.SetDefault("summarizer.max_retries", 3)

	v.SetDefault("jwt.secret", "change-this-secret-key-in-production")
	v.SetDefault("jwt.expiration_hours", 24)
}

func createConfig(v *viper.Viper) *Config {
	cfg := &Config{}

	cfg.Server = ServerConfig{
		Port: v.GetString("server.port"),
		Host: v.GetString("server.host"),
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
		Provider:   v.GetString("summarizer.provider"),
		URL:        v.GetString("summarizer.url"),
		Model:      v.GetString("summarizer.model"),
		APIKey:     v.GetString("summarizer.api_key"),
		MaxRetries: v.GetInt("summarizer.max_retries"),
	}

	cfg.JWT = JWTConfig{
		Secret:          v.GetString("jwt.secret"),
		ExpirationHours: v.GetInt("jwt.expiration_hours"),
	}

	return cfg
}
