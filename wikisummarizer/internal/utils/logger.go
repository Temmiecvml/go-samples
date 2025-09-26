package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const logFilePath = "./logs/app.log"

var (
	ZapLogger    *zap.Logger
	loggerConfig = zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Encoding:    "json", // structured JSON output
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:    "message",
			LevelKey:      "level",
			TimeKey:       "ts",
			NameKey:       "logger",
			CallerKey:     "caller",
			StacktraceKey: "stacktrace",
			LineEnding:    zapcore.DefaultLineEnding,

			// encoders
			EncodeLevel:    zapcore.LowercaseLevelEncoder, // "info", "error"
			EncodeTime:     zapcore.ISO8601TimeEncoder,    // human-readable ISO timestamps
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout", logFilePath},
		ErrorOutputPaths: []string{"stderr"},
	}
)

// InitLogger creates a JSON zap logger that writes to stdout and to logFilePath.
func InitLogger(level *zapcore.Level) error {
	if level != nil {
		loggerConfig.Level.SetLevel(*level)
	}

	if err := os.MkdirAll(filepath.Dir(logFilePath), 0o755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	logger, err := loggerConfig.Build()
	if err != nil {
		return fmt.Errorf("build zap logger: %w", err)
	}

	ZapLogger = logger

	return nil
}

func Debug(msg string, fields ...zap.Field) {
	ZapLogger.Debug("🐛 "+msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	ZapLogger.Info("ℹ️ "+msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	ZapLogger.Warn("⚠️ "+msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	ZapLogger.Error("❌ "+msg, fields...)
}

func SyncLogger() {
	if ZapLogger == nil {
		return
	}
	_ = ZapLogger.Sync() // ignore error per zap docs (some platforms return non-nil)
}
