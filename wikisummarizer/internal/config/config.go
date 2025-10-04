package config

import (
	"fmt"
	"os"

	"go.uber.org/zap/zapcore"
)

func New() *struct {
	Port     string
	LogLevel zapcore.Level
} {
	return &struct {
		Port     string
		LogLevel zapcore.Level
	}{
		Port:     getEnv("PORT", "3000"),
		LogLevel: getLogLevel(),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getLogLevel() zapcore.Level {
	levelStr := getEnv("LOG_LEVEL", "info")
	level, err := zapcore.ParseLevel(levelStr)
	if err != nil {
		fmt.Printf("Invalid log level '%s', defaulting to 'info': %v\n", levelStr, err)
		return zapcore.InfoLevel
	}

	return level
}
