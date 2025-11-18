package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestNewConfig(t *testing.T) {
	t.Parallel()

	t.Run("ValidConfigWithEnvironmentVariables", func(t *testing.T) {
		// Set environment variables using the correct naming convention
		t.Setenv("SERVER_PORT", "8080")
		t.Setenv("SERVER_HOST", "testhost")
		t.Setenv("LOGGING_LEVEL", "debug")
		t.Setenv("DATABASE_PATH", "test.db")
		t.Setenv("SUMMARIZER_PROVIDER", "test_provider")
		t.Setenv("SUMMARIZER_URL", "http://test.url")
		t.Setenv("SUMMARIZER_API_KEY", "test_key")
		t.Setenv("JWT_SECRET", "test_secret")

		cfg, err := New()
		require.NoError(t, err, "Failed to load config")

		assert.Equal(t, "8080", cfg.Server.Port)
		assert.Equal(t, "testhost", cfg.Server.Host)
		assert.Equal(t, zapcore.DebugLevel, cfg.Logging.Level)
		assert.Equal(t, "test.db", cfg.Database.Path)
		assert.Equal(t, "test_provider", cfg.Summarizer.Provider)
		assert.Equal(t, "test_key", cfg.Summarizer.APIKey)
	})

	t.Run("ValidConfigWithDefaults", func(t *testing.T) {
		// Clear all environment variables to test defaults
		// Note: t.Setenv automatically cleans up after test
		cfg, err := New()
		require.NoError(t, err, "Failed to load config with defaults")

		// Test default values
		assert.Equal(t, "3000", cfg.Server.Port)
		assert.Equal(t, "localhost", cfg.Server.Host)
		assert.Equal(t, zapcore.InfoLevel, cfg.Logging.Level)
		assert.Equal(t, "./data/wikisummarizer.db", cfg.Database.Path)
		assert.Equal(t, "ollama", cfg.Summarizer.Provider)
	})

	t.Run("InvalidLogLevelFallsBackToInfo", func(t *testing.T) {
		t.Setenv("LOGGING_LEVEL", "invalid_level")

		cfg, err := New()
		require.NoError(t, err, "Config should load even with invalid log level")
		assert.Equal(t, zapcore.InfoLevel, cfg.Logging.Level, "Should fall back to Info level for invalid input")
	})
}

func TestConfigPrecedence(t *testing.T) {
	t.Parallel()

	// Create a temporary config file for testing
	tempDir := t.TempDir()
	configContent := `
server:
  port: 7000
  host: configfilehost
database:
  path: /tmp/configfile.db
summarizer:
  provider: config_provider
`
	configPath := filepath.Join(tempDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Change to temp directory and restore original after test
	originalWd, _ := os.Getwd()
	err = os.Chdir(tempDir)
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	// Set environment variables - should override config file
	t.Setenv("SERVER_PORT", "9000")
	t.Setenv("DATABASE_PATH", "/tmp/env.db")

	cfg, err := New()
	require.NoError(t, err)

	// Environment variables should override config file
	assert.Equal(t, "9000", cfg.Server.Port, "Environment variable should override config file")
	assert.Equal(t, "/tmp/env.db", cfg.Database.Path, "Environment variable should override config file")

	// Config file should override defaults for values not set in env
	assert.Equal(t, "configfilehost", cfg.Server.Host, "Config file value should be used when no env var")
	assert.Equal(t, "config_provider", cfg.Summarizer.Provider, "Config file value should be used when no env var")
}

func TestDefaultValues(t *testing.T) {
	t.Parallel()

	// Test with clean environment to ensure defaults
	cfg, err := New()
	require.NoError(t, err)

	assert.Equal(t, "3000", cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Server.Host)
	assert.Equal(t, zapcore.InfoLevel, cfg.Logging.Level)
	assert.Equal(t, false, cfg.Logging.Development)
	assert.Equal(t, "json", cfg.Logging.Encoding)
	assert.Equal(t, []string{"stdout", "./logs/app.log"}, cfg.Logging.OutputPaths)
	assert.Equal(t, "sqlite3", cfg.Database.Driver)
	assert.Equal(t, "./data/wikisummarizer.db", cfg.Database.Path)
	assert.Equal(t, 25, cfg.Database.MaxOpenConns)
	assert.Equal(t, 5, cfg.Database.MaxIdleConns)
	assert.Equal(t, 5*time.Minute, cfg.Database.ConnMaxLifetime)
	assert.Equal(t, "ollama", cfg.Summarizer.Provider)
	assert.Equal(t, "http://localhost:11434", cfg.Summarizer.URL)
	assert.Equal(t, "llama2", cfg.Summarizer.Model)
	assert.Equal(t, "", cfg.Summarizer.APIKey)
	assert.Equal(t, 3, cfg.Summarizer.MaxRetries)
	assert.Equal(t, "change-this-secret-key-in-production", cfg.JWT.Secret)
	assert.Equal(t, 24, cfg.JWT.ExpirationHours)
}

func TestEnvironmentOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		envKey   string
		envValue string
		check    func(*testing.T, *Config)
	}{
		{
			name:     "SERVER_PORT override",
			envKey:   "SERVER_PORT",
			envValue: "8000",
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "8000", cfg.Server.Port)
			},
		},
		{
			name:     "DATABASE_PATH override",
			envKey:   "DATABASE_PATH",
			envValue: "/tmp/override.db",
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "/tmp/override.db", cfg.Database.Path)
			},
		},
		{
			name:     "LOGGING_LEVEL override",
			envKey:   "LOGGING_LEVEL",
			envValue: "warn",
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, zapcore.WarnLevel, cfg.Logging.Level)
			},
		},
		{
			name:     "DATABASE_CONN_MAX_LIFETIME override",
			envKey:   "DATABASE_CONN_MAX_LIFETIME",
			envValue: "10m",
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 10*time.Minute, cfg.Database.ConnMaxLifetime)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)

			cfg, err := New()
			require.NoError(t, err)

			tt.check(t, cfg)
		})
	}
}

func TestConfigFileNotFoundIsOk(t *testing.T) {
	t.Parallel()

	// Use a temporary directory with no config file
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	err := os.Chdir(tempDir)
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	// This should not error even though config file doesn't exist
	cfg, err := New()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestDotEnvLoading(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create .env file
	envContent := `SERVER_PORT=9999
SERVER_HOST=envhost
DATABASE_PATH=./env/test.db
LOGGING_LEVEL=error
`
	envPath := filepath.Join(tempDir, ".env")
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)

	originalWd, _ := os.Getwd()
	err = os.Chdir(tempDir)
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	cfg, err := New()
	require.NoError(t, err)

	assert.Equal(t, "9999", cfg.Server.Port)
	assert.Equal(t, "envhost", cfg.Server.Host)
	assert.Equal(t, "./env/test.db", cfg.Database.Path)
	assert.Equal(t, zapcore.ErrorLevel, cfg.Logging.Level)
}

func TestConfigImmutable(t *testing.T) {
	t.Parallel()

	cfg1, err := New()
	require.NoError(t, err)

	cfg2, err := New()
	require.NoError(t, err)

	// Configs should be equal when loaded under same conditions
	assert.Equal(t, cfg1, cfg2)

	// Modifying one should not affect the other
	originalPort := cfg1.Server.Port
	cfg2.Server.Port = "modified"
	assert.Equal(t, originalPort, cfg1.Server.Port, "Original config should not be modified")
}
