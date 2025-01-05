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

type OtpRepository interface {
	Create(ctx context.Context, tx *sqlx.Tx, otp entities.Otp) (entities.Otp, error)
	UpdateOtpUsedAt(ctx context.Context, tx *sqlx.Tx, data entities.OtpUpdateUsedAt) error
	FindOneUserOTP(ctx context.Context, db *sqlx.DB, userID uuid.UUID, otpCode string) (entities.Otp, error)
	IsUserCanRequestOtp(ctx context.Context, db *sqlx.DB, userID uuid.UUID, otpType string) (bool, error)
}

type otpRepository struct{}

func (r *otpRepository) Create(ctx context.Context, tx *sqlx.Tx, otp entities.Otp) (entities.Otp, error) {
	query := `INSERT INTO otp (user_id, otp_code, otp_type, expires_at, created_at) 
				VALUES (:user_id, :otp_code, :otp_type, :expires_at, :created_at) 
				RETURNING id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return entities.Otp{}, fmt.Errorf("[%s|Create] failed to prepare named statement: %w", otpRN, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	rows, err := stmt.QueryxContext(ctx, otp)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" {
				return entities.Otp{}, dbErrors.DBErrConflict
			}
		}
		return entities.Otp{}, fmt.Errorf("[%s|Create] %s: %w", otpRN, errExecQuery, err)
	}
	defer dbHelpers.DbCloseRows(rows)

	// Fetch the returned ID
	if rows.Next() {
		err := rows.Scan(&otp.ID)
		if err != nil {
			return entities.Otp{}, fmt.Errorf("[%s|Create] %s: %w", otpRN, errFailedScan, err)
		}
	} else {
		return entities.Otp{}, fmt.Errorf("[%s|Create] %s", otpRN, errNoRows)
	}

	return otp, nil
}

func (r *otpRepository) UpdateOtpUsedAt(ctx context.Context, tx *sqlx.Tx, data entities.OtpUpdateUsedAt) error {
	query := `UPDATE otp SET used_at = NOW() WHERE id = $1`

	_, err := tx.ExecContext(ctx, query, data.ID)
	if err != nil {
		return fmt.Errorf("[%s|UpdateOtpUsedAt] %s: %w", otpRN, errExecQuery, err)
	}

	return nil
}

func (r *otpRepository) FindOneUserOTP(ctx context.Context, db *sqlx.DB, userID uuid.UUID, otpCode string) (entities.Otp, error) {
	query := `SELECT * FROM otp WHERE user_id = $1 AND otp_code = $2 AND deleted_at IS NULL`

	var otp entities.Otp
	err := db.GetContext(ctx, &otp, query, userID, otpCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entities.Otp{}, dbErrors.DBErrNotFound
		}
		return entities.Otp{}, fmt.Errorf("[%s|FindOneUserOTP] %s: %w", otpRN, errExecQuery, err)
	}

	return otp, nil
}

func (r *otpRepository) IsUserCanRequestOtp(ctx context.Context, db *sqlx.DB, userID uuid.UUID, otpType string) (bool, error) {
	query := `SELECT COUNT(*) FROM otp 
                WHERE user_id = $1 
                  AND otp_type = $2  
                  AND expires_at > NOW() - INTERVAL '10 minutes'`

	var count int
	err := db.GetContext(ctx, &count, query, userID, otpType)
	if err != nil {
		return false, fmt.Errorf("[%s|CanUserRequestOtp] %s: %w", otpRN, errExecQuery, err)
	}

	return count < 3, nil
}

func NewOtpRepository() OtpRepository {
	return &otpRepository{}
}
