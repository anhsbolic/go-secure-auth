package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/anhsbolic/go-secure-auth/pkg/dbErrors"
	"github.com/anhsbolic/go-secure-auth/pkg/dbHelpers"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type TokenRepository interface {
	Create(ctx context.Context, tx *sqlx.Tx, token entities.Token) (entities.Token, error)
	UpdateTokenUsedAt(ctx context.Context, tx *sqlx.Tx, data entities.TokenUpdateUsedAt) error
	UpdateTokenRevokedAt(ctx context.Context, tx *sqlx.Tx, data entities.TokenUpdateRevokedAt) error
	RevokeUserTokens(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, tokenType string) error
	FindOneByUserToken(ctx context.Context, db *sqlx.DB, userID uuid.UUID, token string) (entities.Token, error)
}

type tokenRepository struct{}

func (r *tokenRepository) Create(ctx context.Context, tx *sqlx.Tx, token entities.Token) (entities.Token, error) {
	query := `INSERT INTO tokens (user_id, token_hash, token_type, expires_at, created_at) 
				VALUES (:user_id, :token_hash, :token_type, :expires_at, :created_at) 
				RETURNING id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return entities.Token{}, fmt.Errorf("[%s|Create] failed to prepare named statement: %w", tknRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	rows, err := stmt.QueryxContext(ctx, token)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" {
				return entities.Token{}, dbErrors.DBErrConflict
			}
		}
		return entities.Token{}, fmt.Errorf("[%s|Create] %s: %w", tknRN, errExecQuery, err)
	}
	defer dbHelpers.DbCloseRows(rows)

	// Fetch the returned ID
	if rows.Next() {
		err := rows.Scan(&token.ID)
		if err != nil {
			return entities.Token{}, fmt.Errorf("[%s|Create] %s: %w", tknRN, errFailedScan, err)
		}
	} else {
		return entities.Token{}, fmt.Errorf("[%s|Create] %s", tknRN, errNoRows)
	}

	return token, nil
}

func (r *tokenRepository) UpdateTokenUsedAt(ctx context.Context, tx *sqlx.Tx, data entities.TokenUpdateUsedAt) error {
	query := `UPDATE tokens SET used_at = :used_at WHERE id = :id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return fmt.Errorf("[%s|UpdateTokenUsedAt] failed to prepare named statement: %w", tknRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	_, err = stmt.ExecContext(ctx, data)
	if err != nil {
		return fmt.Errorf("[%s|UpdateTokenUsedAt] %s: %w", tknRN, errExecQuery, err)
	}

	return nil
}

func (r *tokenRepository) UpdateTokenRevokedAt(ctx context.Context, tx *sqlx.Tx, data entities.TokenUpdateRevokedAt) error {
	query := `UPDATE tokens SET revoked_at = :revoked_at WHERE id = :id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return fmt.Errorf("[%s|UpdateTokenRevokedAt] failed to prepare named statement: %w", tknRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	_, err = stmt.ExecContext(ctx, data)
	if err != nil {
		return fmt.Errorf("[%s|UpdateTokenRevokedAt] %s: %w", tknRN, errExecQuery, err)
	}

	return nil
}

func (r *tokenRepository) RevokeUserTokens(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, tokenType string) error {
	query := `UPDATE tokens SET revoked_at = NOW() 
              WHERE user_id = $1 
                AND token_type = $2 
                AND revoked_at IS NULL
                AND deleted_at IS NULL`

	// Execute the query
	_, err := tx.ExecContext(ctx, query, userID, tokenType)
	if err != nil {
		return fmt.Errorf("[%s|RevokeUserTokens] %s: %w", tknRN, errExecQuery, err)
	}

	return nil
}

func (r *tokenRepository) FindOneByUserToken(ctx context.Context, db *sqlx.DB, userID uuid.UUID, token string) (entities.Token, error) {
	query := `SELECT * FROM tokens WHERE user_id = $1 AND token_hash = $2 AND deleted_at IS NULL`

	var tkn entities.Token
	err := db.GetContext(ctx, &tkn, query, userID, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entities.Token{}, dbErrors.DBErrNotFound
		}
		return entities.Token{}, fmt.Errorf("[%s|FindOneByUserToken] %s: %w", tknRN, errExecQuery, err)
	}

	return tkn, nil
}

func NewTokenRepository() TokenRepository {
	return &tokenRepository{}
}
