package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
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
func InitLogger(level *zapcore.Level) (*zap.Logger, error) {
	if level != nil {
		loggerConfig.Level.SetLevel(*level)
	}

	// Ensure the log directory exists
	if err := os.MkdirAll(filepath.Dir(logFilePath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Build the logger
	logger, err := loggerConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build zap logger: %w", err)
	}

	ZapLogger = logger

	return ZapLogger, nil
}

func InitLoggerRotating(level zapcore.Level) (*zap.Logger, error) {

	if err := os.MkdirAll(filepath.Dir(logFilePath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Encoder (JSON)
	encCfg := zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "level",
		TimeKey:        "ts",
		CallerKey:      "caller",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}
	encoder := zapcore.NewJSONEncoder(encCfg)

	// lumberjack writer for rotation
	lumberjackWriter := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    100, // MB
		MaxBackups: 7,
		MaxAge:     28, // days
		Compress:   true,
	}

	fileWS := zapcore.AddSync(lumberjackWriter) // WriteSyncer for file
	consoleWS := zapcore.Lock(os.Stdout)

	// Per-sink level enablers (optional)
	fileLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= zapcore.InfoLevel })
	consoleLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool { return lvl >= level })

	// Create cores and combine
	cores := []zapcore.Core{
		zapcore.NewCore(encoder, consoleWS, consoleLevel),
		zapcore.NewCore(encoder, fileWS, fileLevel),
	}
	core := zapcore.NewTee(cores...)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	ZapLogger = logger
	return ZapLogger, nil
}

func GetLogger(name string) *zap.Logger {
	if ZapLogger == nil {
		return zap.NewNop().Named(name)
	}
	return ZapLogger.Named(name)
}
