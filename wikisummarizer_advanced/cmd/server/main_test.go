package main

import (
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	os.Setenv("DATABASE_PATH", ":memory:")
	os.Setenv("LOG_LEVEL", "error")

	code := m.Run()

	os.Unsetenv("DATABASE_PATH")
	os.Unsetenv("LOG_LEVEL")

	os.Exit(code)
}

func TestRun(t *testing.T) {
	os.Setenv("PORT", "0")
	t.Cleanup(func() {
		os.Unsetenv("PORT")
	})

	go func() {
		time.Sleep(100 * time.Millisecond)
		// Application would start here in real scenario
	}()
}
