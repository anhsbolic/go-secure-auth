package entities

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

type UserSession struct {
	ID            uuid.UUID    `db:"id"`
	SessionID     uuid.UUID    `db:"session_id"`
	UserID        uuid.UUID    `db:"user_id"`
	Alias         uuid.UUID    `db:"alias"`
	AccessUUID    uuid.UUID    `db:"access_uuid"`
	RefreshUUID   uuid.UUID    `db:"refresh_uuid"`
	UserAgent     []byte       `db:"user_agent"`
	UserAgentHash string       `db:"user_agent_hash"`
	IPAddress     []byte       `db:"ip_address"`
	IPAddressHash string       `db:"ip_address_hash"`
	ExpiresAt     time.Time    `db:"expires_at"`
	RevokedAt     sql.NullTime `db:"revoked_at,omitempty"`
	CreatedAt     sql.NullTime `db:"created_at"`
	UpdatedAt     sql.NullTime `db:"updated_at"`
	DeletedAt     sql.NullTime `db:"deleted_at,omitempty"`
}

type UserSessionUpdateUsedAt struct {
	ID     uuid.UUID `db:"id"`
	UsedAt time.Time `db:"used_at"`
}

type UserSessionUpdateRevokedAt struct {
	ID        uuid.UUID `db:"id"`
	RevokedAt time.Time `db:"revoked_at"`
}

type UserSessionMetadata struct {
	UserID        uuid.UUID `db:"user_id"`
	UserAgentHash string    `db:"user_agent_hash"`
	IPAddressHash string    `db:"ip_address_hash"`
}
