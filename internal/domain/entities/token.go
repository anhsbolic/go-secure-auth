package entities

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

const (
	TokenTypeEmailVerification = "email_verification"
	TokenTypeResetPassword     = "reset_password"
)

type Token struct {
	ID        uuid.UUID    `db:"id"`
	UserID    uuid.UUID    `db:"user_id"`
	TokenHash string       `db:"token_hash"`
	TokenType string       `db:"token_type"`
	ExpiresAt time.Time    `db:"expires_at"`
	UsedAt    sql.NullTime `db:"used_at,omitempty"`
	RevokedAt sql.NullTime `db:"revoked_at,omitempty"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	DeletedAt sql.NullTime `db:"deleted_at,omitempty"`
}

type TokenUpdateUsedAt struct {
	ID     uuid.UUID `db:"id"`
	UsedAt time.Time `db:"used_at"`
}

type TokenUpdateRevokedAt struct {
	ID        uuid.UUID `db:"id"`
	RevokedAt time.Time `db:"revoked_at"`
}
