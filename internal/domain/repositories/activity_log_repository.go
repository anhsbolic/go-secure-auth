package repositories

import (
	"context"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/jmoiron/sqlx"
)

type ActivityLogRepository interface {
	Create(ctx context.Context, db *sqlx.DB, userActivityLog entities.ActivityLog) error
	CreateTx(ctx context.Context, tx *sqlx.Tx, userActivityLog entities.ActivityLog) error
}

type activityLogRepository struct{}

func (r *activityLogRepository) Create(ctx context.Context, db *sqlx.DB, userActivityLog entities.ActivityLog) error {
	query := `INSERT INTO activity_logs (user_id, ip_address, ip_address_hash, user_agent, user_agent_hash, 
                           activity, activity_time, description, created_at) 
				VALUES (:user_id, :ip_address, :ip_address_hash, :user_agent, :user_agent_hash, 
				        :activity, :activity_time, :description, :created_at)`

	_, err := db.NamedExecContext(ctx, query, userActivityLog)
	if err != nil {
		return fmt.Errorf("[%s|Create] %s: %w", alRN, errExecQuery, err)
	}

	return nil
}

func (r *activityLogRepository) CreateTx(ctx context.Context, tx *sqlx.Tx, userActivityLog entities.ActivityLog) error {
	query := `INSERT INTO activity_logs (user_id, ip_address, ip_address_hash, user_agent, user_agent_hash, 
						   activity, activity_time, description, created_at) 
				VALUES (:user_id, :ip_address, :ip_address_hash, :user_agent, :user_agent_hash, 
				        :activity, :activity_time, :description, :created_at)`

	_, err := tx.NamedExecContext(ctx, query, userActivityLog)
	if err != nil {
		return fmt.Errorf("[%s|CreateTx] %s: %w", alRN, errExecQuery, err)
	}

	return nil
}

func NewActivityLogRepository() ActivityLogRepository {
	return &activityLogRepository{}
}
