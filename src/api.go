package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

// Hash a string using SHA-256
func hashString(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return hex.EncodeToString(hash.Sum(nil))
}

// GenerateToken creates a JWT token for a user
func GenerateToken(userID string, secretKey []byte, expiration time.Duration) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// JWTClaims defines the structure of the JWT claims
type JWTClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

// JWTMiddleware returns a middleware handler that validates JWT tokens
func JWTMiddleware(secretKey []byte) func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tokenStr := r.Header.Get("Authorization")
            if tokenStr == "" {
                fmt.Println("Authorization header missing")
                http.Error(w, "Authorization header missing", http.StatusUnauthorized)
                return
            }

            if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
                tokenStr = tokenStr[7:]
            } else {
                fmt.Println("Invalid token format")
                http.Error(w, "Invalid token format", http.StatusUnauthorized)
                return
            }

            token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
                return secretKey, nil
            })

            if err != nil || !token.Valid {
                fmt.Printf("Invalid token: %v\n", err)
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            claims, ok := token.Claims.(*JWTClaims)
            if !ok {
                fmt.Println("Invalid token claims")
                http.Error(w, "Invalid token claims", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), "userID", claims.UserID)
            r = r.WithContext(ctx)

            next.ServeHTTP(w, r)
        })
    }
}

// APIConfig holds configuration options for the API
type APIConfig struct {
	SecretKey       []byte
	TokenExpiration time.Duration
}

// Option is a function that configures APIConfig
type Option func(*APIConfig)

// WithSecretKey sets the JWT secret key
func WithSecretKey(key string) Option {
	return func(cfg *APIConfig) {
		cfg.SecretKey = []byte(key)
	}
}

// WithTokenExpiration sets the JWT token expiration duration
func WithTokenExpiration(duration time.Duration) Option {
	return func(cfg *APIConfig) {
		cfg.TokenExpiration = duration
	}
}

// NewAPIConfig creates a new APIConfig with default values and applies options
func NewAPIConfig(opts ...Option) *APIConfig {
	cfg := &APIConfig{
		SecretKey:       []byte("default-secret-key"),
		TokenExpiration: time.Hour * 24,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
