package entities

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

const (
	UserStatusActive   = "active"
	UserStatusInactive = "inactive"
	UserStatusBlocked  = "blocked"
	UserRoleMember     = "member"
)

type User struct {
	ID              uuid.UUID    `db:"id"`
	Username        []byte       `db:"username"`
	UsernameHash    string       `db:"username_hash"`
	Email           []byte       `db:"email"`
	EmailHash       string       `db:"email_hash"`
	PasswordHash    string       `db:"password_hash"`
	Role            string       `db:"role"`
	Status          string       `db:"status"`
	EmailVerifiedAt sql.NullTime `db:"email_verified_at"`
	CreatedAt       sql.NullTime `db:"created_at"`
	UpdatedAt       sql.NullTime `db:"updated_at"`
	DeletedAt       sql.NullTime `db:"deleted_at,omitempty"`
}

type UpdateEmailVerifiedUser struct {
	ID              uuid.UUID `db:"id"`
	Status          string    `db:"status"`
	EmailVerifiedAt time.Time `db:"email_verified_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

type UpdatePasswordUser struct {
	ID           uuid.UUID `db:"id"`
	PasswordHash string    `db:"password_hash"`
	UpdatedAt    time.Time `db:"updated_at"`
}
