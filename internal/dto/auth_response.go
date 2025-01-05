package dto

import (
	"github.com/google/uuid"
	"time"
)

type RegisterResponse struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Status       string    `json:"status"`
	RegisteredAt time.Time `json:"registered_at"`
}

type VerifyLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
