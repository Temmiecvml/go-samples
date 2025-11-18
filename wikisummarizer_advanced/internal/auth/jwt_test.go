package auth

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	jwtService := NewJWTService("test-secret", 24)

	token, err := jwtService.GenerateToken(1, "testuser", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		userID    int
		username  string
		role      string
		secret    string
		wantError bool
	}{
		{
			name:      "valid token",
			userID:    1,
			username:  "testuser",
			role:      "admin",
			secret:    "test-secret",
			wantError: false,
		},
		{
			name:      "different user",
			userID:    2,
			username:  "another",
			role:      "user",
			secret:    "test-secret",
			wantError: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jwtService := NewJWTService(tt.secret, 24)

			token, err := jwtService.GenerateToken(tt.userID, tt.username, tt.role)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			claims, err := jwtService.ValidateToken(token)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateToken() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if claims.UserID != tt.userID {
					t.Errorf("Expected UserID %d, got %d", tt.userID, claims.UserID)
				}

				wantClaims := Claims{
					UserID:   tt.userID,
					Username: tt.username,
					Role:     tt.role,
				}

				if diff := cmp.Diff(wantClaims.Username, claims.Username); diff != "" {
					t.Errorf("Claims mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExpiredToken(t *testing.T) {
	t.Parallel()

	jwtService := NewJWTService("test-secret", 0)
	jwtService.expiry = -1 * time.Hour

	token, err := jwtService.GenerateToken(1, "testuser", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = jwtService.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got %v", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	t.Parallel()

	jwtService1 := NewJWTService("secret1", 24)
	jwtService2 := NewJWTService("secret2", 24)

	token, err := jwtService1.GenerateToken(1, "testuser", "admin")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = jwtService2.ValidateToken(token)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestHashPassword(t *testing.T) {
	t.Parallel()

	password := "testpassword"
	hashed := HashPassword(password)

	if hashed == "" {
		t.Error("Expected non-empty hash")
	}

	if hashed == password {
		t.Error("Hash should not equal password")
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	password := "testpassword"
	hashed := HashPassword(password)

	if !VerifyPassword(hashed, password) {
		t.Error("Password verification failed")
	}

	if VerifyPassword(hashed, "wrongpassword") {
		t.Error("Wrong password should not verify")
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	jwtService := NewJWTService("test-secret", 24)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwtService.GenerateToken(1, "testuser", "admin")
	}
}

func BenchmarkValidateToken(b *testing.B) {
	jwtService := NewJWTService("test-secret", 24)
	token, _ := jwtService.GenerateToken(1, "testuser", "admin")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwtService.ValidateToken(token)
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = HashPassword("testpassword")
	}
}

func FuzzHashPassword(f *testing.F) {
	f.Add("password")
	f.Add("123456")
	f.Add("admin")

	f.Fuzz(func(t *testing.T, password string) {
		hash := HashPassword(password)
		if hash == "" {
			t.Error("Hash should not be empty")
		}
	})
}
