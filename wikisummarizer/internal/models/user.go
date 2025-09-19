package models

// User represents a simple user model
// Future fields: Password, Role, etc.
type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
