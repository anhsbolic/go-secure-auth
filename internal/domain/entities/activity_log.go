package entities

import (
	"database/sql"
	"github.com/google/uuid"
)

const (
	ActivityLogLogin          = "login"
	ActivityLogLoggedIn       = "logged_in"
	ActivityLogLogout         = "logout"
	ActivityLogLogoutAll      = "logout_all"
	ActivityLogChangePassword = "change_password"
)

type ActivityLog struct {
	ID            uuid.UUID      `db:"id"`
	UserID        uuid.UUID      `db:"user_id"`
	UserAgent     []byte         `db:"user_agent"`
	UserAgentHash string         `db:"user_agent_hash"`
	IPAddress     []byte         `db:"ip_address"`
	IPAddressHash string         `db:"ip_address_hash"`
	Activity      string         `db:"activity"`
	ActivityTime  sql.NullTime   `db:"activity_time"`
	Description   sql.NullString `db:"description"`
	CreatedAt     sql.NullTime   `db:"created_at"`
	UpdatedAt     sql.NullTime   `db:"updated_at"`
	DeletedAt     sql.NullTime   `db:"deleted_at,omitempty"`
}
