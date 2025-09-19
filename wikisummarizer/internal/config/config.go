package config

import "os"

// AppConfig holds global application configurations.
var AppConfig = struct {
	Port string
}{
	Port: getEnv("APP_PORT", "3000"),
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
