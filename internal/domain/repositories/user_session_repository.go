package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/anhsbolic/go-secure-auth/pkg/dbErrors"
	"github.com/anhsbolic/go-secure-auth/pkg/dbHelpers"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type UserSessionRepository interface {
	Create(ctx context.Context, tx *sqlx.Tx, userSession entities.UserSession) (entities.UserSession, error)
	RefreshSession(ctx context.Context, tx *sqlx.Tx, userSession entities.UserSession) error
	FindOneByMetadata(ctx context.Context, db *sqlx.DB, metadata entities.UserSessionMetadata) (entities.UserSession, error)
}

type userSessionRepository struct{}

func (r *userSessionRepository) Create(ctx context.Context, tx *sqlx.Tx, userSession entities.UserSession) (entities.UserSession, error) {
	query := `INSERT INTO user_sessions (session_id, user_id, alias, access_uuid, refresh_uuid, user_agent, 
                           				user_agent_hash, ip_address, ip_address_hash, expires_at, created_at) 
				VALUES (:session_id, :user_id, :alias, :access_uuid, :refresh_uuid, :user_agent,
				        :user_agent_hash, :ip_address, :ip_address_hash, :expires_at, :created_at) 
				RETURNING id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return entities.UserSession{}, fmt.Errorf("[%s|Create] failed to prepare named statement: %w", usSnRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	rows, err := stmt.QueryxContext(ctx, userSession)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" {
				return entities.UserSession{}, dbErrors.DBErrConflict
			}
		}
		return entities.UserSession{}, fmt.Errorf("[%s|Create] %s: %w", usSnRN, errExecQuery, err)
	}
	defer dbHelpers.DbCloseRows(rows)

	// Fetch the returned ID
	if rows.Next() {
		err := rows.Scan(&userSession.ID)
		if err != nil {
			return entities.UserSession{}, fmt.Errorf("[%s|Create] %s: %w", usSnRN, errFailedScan, err)
		}
	} else {
		return entities.UserSession{}, fmt.Errorf("[%s|Create] %s", usSnRN, errNoRows)
	}

	return userSession, nil
}

func (r *userSessionRepository) RefreshSession(ctx context.Context, tx *sqlx.Tx, userSession entities.UserSession) error {
	query := `UPDATE user_sessions 
		 SET access_uuid = :access_uuid, 
		     refresh_uuid = :refresh_uuid,
		     revoked_at = NULL,
		     expires_at = :expires_at, 
		     updated_at = :updated_at
		 WHERE id = :id AND deleted_at IS NULL`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return fmt.Errorf("[%s|RefreshSession] %s: %w", errFailPrepNameStmt, usSnRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	_, err = stmt.ExecContext(ctx, userSession)
	if err != nil {
		return fmt.Errorf("[%s|RefreshSession] %s: %w", usSnRN, errExecQuery, err)
	}

	return nil
}

func (r *userSessionRepository) FindOneByMetadata(ctx context.Context, db *sqlx.DB, metadata entities.UserSessionMetadata) (entities.UserSession, error) {
	query := `SELECT * FROM user_sessions 
         WHERE user_id = $1
           AND user_agent_hash = $2
           AND ip_address_hash = $3 
           AND deleted_at IS NULL`

	var userSession entities.UserSession
	err := db.GetContext(ctx, &userSession, query, metadata.UserID, metadata.UserAgentHash, metadata.IPAddressHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entities.UserSession{}, dbErrors.DBErrNotFound
		}
		return entities.UserSession{}, fmt.Errorf("[%s|FindOneByMetadata] %s: %w", usSnRN, errExecQuery, err)
	}

	return userSession, nil
}

func NewUserSessionRepository() UserSessionRepository {
	return &userSessionRepository{}
}
