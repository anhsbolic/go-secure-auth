package entities

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

const (
	OtpTypeLogin = "login"
)

type Otp struct {
	ID        uuid.UUID    `db:"id"`
	UserID    uuid.UUID    `db:"user_id"`
	OtpCode   string       `db:"otp_code"`
	OtpType   string       `db:"otp_type"`
	ExpiresAt time.Time    `db:"expires_at"`
	UsedAt    sql.NullTime `db:"used_at,omitempty"`
	CreatedAt sql.NullTime `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	DeletedAt sql.NullTime `db:"deleted_at,omitempty"`
}

type OtpUpdateUsedAt struct {
	ID     uuid.UUID `db:"id"`
	UsedAt time.Time `db:"used_at"`
}
