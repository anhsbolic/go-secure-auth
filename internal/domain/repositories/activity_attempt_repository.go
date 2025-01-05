package repositories

import (
	"context"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"time"
)

type ActivityAttemptRepository interface {
	Create(ctx context.Context, db *sqlx.DB, userActivityAttempt entities.ActivityAttempt) error
	CreateTx(ctx context.Context, tx *sqlx.Tx, userActivityAttempt entities.ActivityAttempt) error
	ResolveLastAttempts(ctx context.Context, db *sqlx.DB, userID uuid.UUID, activity string) error
	ResolveLastAttemptsTx(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, activity string) error
	IsExceedMaxAttempt(ctx context.Context, db *sqlx.DB, userID uuid.UUID, activity string, maxAttempts int, timeFrame time.Duration) (bool, error)
}

type activityAttemptRepository struct{}

func (r *activityAttemptRepository) Create(ctx context.Context, db *sqlx.DB, userActivityAttempt entities.ActivityAttempt) error {
	query := `INSERT INTO activity_attempts (user_id,  activity, attempt_time, success, description, created_at) 
				VALUES (:user_id, :activity, :attempt_time, :success, :description, :created_at)`

	_, err := db.NamedExecContext(ctx, query, userActivityAttempt)
	if err != nil {
		return fmt.Errorf("[%s|Create] %s: %w", aaRN, errExecQuery, err)
	}

	return nil
}

func (r *activityAttemptRepository) CreateTx(ctx context.Context, tx *sqlx.Tx, userActivityAttempt entities.ActivityAttempt) error {
	query := `INSERT INTO activity_attempts (user_id,  activity, attempt_time, success, description, created_at) 
				VALUES (:user_id, :activity, :attempt_time, :success, :description, :created_at)`

	_, err := tx.NamedExecContext(ctx, query, userActivityAttempt)
	if err != nil {
		return fmt.Errorf("[%s|CreateTx] %s: %w", aaRN, errExecQuery, err)
	}

	return nil
}

func (r *activityAttemptRepository) ResolveLastAttempts(ctx context.Context, db *sqlx.DB, userID uuid.UUID, activity string) error {
	query := `WITH failed_attempts AS (
				SELECT id
				FROM activity_attempts
				WHERE user_id = $1
				  AND activity = $2
				  AND success = FALSE
				  AND resolved_at IS NULL
				ORDER BY attempt_time DESC
				LIMIT 10
			)
			UPDATE activity_attempts
			SET resolved_at = NOW()
			WHERE id IN (SELECT id FROM failed_attempts)`

	_, err := db.ExecContext(ctx, query, userID, activity)
	if err != nil {
		return fmt.Errorf("[%s|ResolveLastAttempts] %s: %w", aaRN, errExecQuery, err)
	}

	return nil
}

func (r *activityAttemptRepository) ResolveLastAttemptsTx(ctx context.Context, tx *sqlx.Tx, userID uuid.UUID, activity string) error {
	query := `WITH failed_attempts AS (
				SELECT id
				FROM activity_attempts
				WHERE user_id = $1
				  AND activity = $2
				  AND success = FALSE
				  AND resolved_at IS NULL
				ORDER BY attempt_time DESC
				LIMIT 10
			)
			UPDATE activity_attempts
			SET resolved_at = NOW()
			WHERE id IN (SELECT id FROM failed_attempts)`

	_, err := tx.ExecContext(ctx, query, userID, activity)
	if err != nil {
		return fmt.Errorf("[%s|ResolveLastAttemptsTx] %s: %w", aaRN, errExecQuery, err)
	}

	return nil
}

func (r *activityAttemptRepository) IsExceedMaxAttempt(
	ctx context.Context,
	db *sqlx.DB,
	userID uuid.UUID,
	activity string,
	maxAttempts int,
	timeFrame time.Duration,
) (bool, error) {
	query := `SELECT COUNT(*) FROM activity_attempts 
				WHERE user_id = $1 
				  AND activity = $2 
				  AND success = false 
				  AND resolved_at IS NULL
				  AND attempt_time > now() - $3::interval`

	var count int
	interval := fmt.Sprintf("%d seconds", int64(timeFrame.Seconds()))
	err := db.GetContext(ctx, &count, query, userID, activity, interval)
	if err != nil {
		return false, fmt.Errorf("[%s|IsExceedMaxLoginAttempt] %s: %w", aaRN, errExecQuery, err)
	}

	return count >= maxAttempts, nil
}

func NewActivityAttemptRepository() ActivityAttemptRepository {
	return &activityAttemptRepository{}
}
