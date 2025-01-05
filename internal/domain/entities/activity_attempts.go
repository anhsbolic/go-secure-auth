package entities

import (
	"database/sql"
	"github.com/google/uuid"
)

const (
	ActivityAttemptLogin       = "login"
	ActivityAttemptVerifyLogin = "verify_login"
)

type ActivityAttempt struct {
	ID          uuid.UUID      `db:"id"`
	UserID      uuid.UUID      `db:"user_id"`
	Activity    string         `db:"activity"`
	AttemptTime sql.NullTime   `db:"attempt_time"`
	Success     bool           `db:"success"`
	Description sql.NullString `db:"description"`
	ResolvedAt  sql.NullTime   `db:"resolved_at"`
	CreatedAt   sql.NullTime   `db:"created_at"`
	UpdatedAt   sql.NullTime   `db:"updated_at"`
	DeletedAt   sql.NullTime   `db:"deleted_at,omitempty"`
}
