package models

type Settings struct {
	ID             int    `json:"id" db:"id"`
	SummarizerType string `json:"summarizer_type" db:"summarizer_type"`
	OllamaURL      string `json:"ollama_url" db:"ollama_url"`
	OllamaModel    string `json:"ollama_model" db:"ollama_model"`
	GeminiAPIKey   string `json:"gemini_api_key" db:"gemini_api_key"`
	GeminiModel    string `json:"gemini_model" db:"gemini_model"`
}
