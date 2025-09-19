package utils

import (
	"log"
	"os"
)

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
)

func InitLogger() {
	InfoLogger = log.New(os.Stdout, "ℹ️ INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "❌ ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func LogInfo(message string) {
	InfoLogger.Println(message)
}

func LogError(message string) {
	ErrorLogger.Println(message)
}
