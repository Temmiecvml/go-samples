package main

import (
	"fmt"
	"log"

	"github.com/temmiecvml/go-samples/wikipedia_summarizer/internal/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Wikipedia summarizer failed %v", err)
	}
}

func run() error {
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("configuration failed %v", err)
	}

	fmt.Print(cfg)

	return nil
}
