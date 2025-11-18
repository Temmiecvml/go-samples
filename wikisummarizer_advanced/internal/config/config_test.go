package config

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap/zapcore"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	os.Setenv("PORT", "8080")
	os.Setenv("LOG_LEVEL", "debug")
	t.Cleanup(func() {
		os.Unsetenv("PORT")
		os.Unsetenv("LOG_LEVEL")
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port != "8080" {
		t.Errorf("Expected port 8080, got %s", cfg.Server.Port)
	}

	if cfg.Logging.Level != zapcore.DebugLevel {
		t.Errorf("Expected debug level, got %v", cfg.Logging.Level)
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port == "" {
		t.Error("Expected default port")
	}

	if cfg.Database.Driver != "sqlite3" {
		t.Errorf("Expected sqlite3 driver, got %s", cfg.Database.Driver)
	}

	if cfg.Wikipedia.MaxArticles == 0 {
		t.Error("Expected default max articles")
	}
}

func TestTimeouts(t *testing.T) {
	t.Parallel()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.ReadTimeout < time.Second {
		t.Error("Read timeout too small")
	}

	if cfg.Server.WriteTimeout < time.Second {
		t.Error("Write timeout too small")
	}
}

func TestLoadWithEnvVariables(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		check    func(*Config) error
	}{
		{
			name:     "PORT override",
			envKey:   "PORT",
			envValue: "9000",
			check: func(cfg *Config) error {
				if cfg.Server.Port != "9000" {
					t.Errorf("Expected port 9000, got %s", cfg.Server.Port)
				}
				return nil
			},
		},
		{
			name:     "DATABASE_PATH override",
			envKey:   "DATABASE_PATH",
			envValue: "/tmp/test.db",
			check: func(cfg *Config) error {
				if cfg.Database.Path != "/tmp/test.db" {
					t.Errorf("Expected /tmp/test.db, got %s", cfg.Database.Path)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.envKey, tt.envValue)
			t.Cleanup(func() {
				os.Unsetenv(tt.envKey)
			})

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if err := tt.check(cfg); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestConfigComparison(t *testing.T) {
	cfg1, _ := Load()
	cfg2, _ := Load()

	if diff := cmp.Diff(cfg1.Server.Port, cfg2.Server.Port); diff != "" {
		t.Errorf("Config mismatch (-want +got):\n%s", diff)
	}
}
