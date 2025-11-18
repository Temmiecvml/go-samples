package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/temmiecvml/go-samples/wikisummarizer/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func InitLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create log directory: %w", err)
			}
		}
	}

	encoderCfg := zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "level",
		TimeKey:        "ts",
		CallerKey:      "caller",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if cfg.Encoding == "json" {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	}

	var cores []zapcore.Core

	consoleWS := zapcore.Lock(os.Stdout)
	cores = append(cores, zapcore.NewCore(encoder, consoleWS, cfg.Level))

	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			fileWS := zapcore.AddSync(&lumberjack.Logger{
				Filename:   path,
				MaxSize:    100,
				MaxBackups: 7,
				MaxAge:     28,
				Compress:   true,
			})
			cores = append(cores, zapcore.NewCore(encoder, fileWS, zapcore.InfoLevel))
		}
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}
