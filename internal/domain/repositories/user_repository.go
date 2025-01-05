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

type UserRepository interface {
	Create(ctx context.Context, tx *sqlx.Tx, user entities.User) (entities.User, error)
	UpdateEmailVerified(ctx context.Context, tx *sqlx.Tx, user entities.UpdateEmailVerifiedUser) error
	UpdatePassword(ctx context.Context, tx *sqlx.Tx, user entities.UpdatePasswordUser) error
	CheckByID(ctx context.Context, db *sqlx.DB, id string) (bool, error)
	CheckByUsernameHash(ctx context.Context, db *sqlx.DB, usernameHash string) (bool, error)
	CheckByEmailHash(ctx context.Context, db *sqlx.DB, emailHash string) (bool, error)
	FindOneByID(ctx context.Context, db *sqlx.DB, id string) (entities.User, error)
	FindOneByEmailHash(ctx context.Context, db *sqlx.DB, emailHash string) (entities.User, error)
}

type userRepository struct{}

func (r *userRepository) Create(ctx context.Context, tx *sqlx.Tx, user entities.User) (entities.User, error) {
	query := `INSERT INTO users (username, username_hash, email, email_hash, password_hash, role, status, created_at) 
				VALUES (:username, :username_hash, :email, :email_hash, :password_hash, :role, :status, :created_at) 
				RETURNING id`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return entities.User{}, fmt.Errorf("[%s|Create] %s: %w", usrRN, errFailPrepNameStmt, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	rows, err := stmt.QueryxContext(ctx, user)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			if pqErr.Code == "23505" {
				return entities.User{}, dbErrors.DBErrConflict
			}
		}
		return entities.User{}, fmt.Errorf("[%s|Create] %s: %w", usrRN, errExecQuery, err)
	}
	defer dbHelpers.DbCloseRows(rows)

	// Fetch the returned ID
	if rows.Next() {
		err := rows.Scan(&user.ID)
		if err != nil {
			return entities.User{}, fmt.Errorf("[%s|Create] %s: %w", usrRN, errFailedScan, err)
		}
	} else {
		return entities.User{}, fmt.Errorf("[%s|Create] %s", usrRN, errNoRows)
	}

	return user, nil
}

func (r *userRepository) UpdateEmailVerified(ctx context.Context, tx *sqlx.Tx, user entities.UpdateEmailVerifiedUser) error {
	query := `UPDATE users SET status = :status, email_verified_at = :email_verified_at, updated_at = :updated_at 
             WHERE id = :id 
               AND deleted_at IS NULL`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return fmt.Errorf("[%s|UpdateEmailVerified] %s: %w", usrRN, errFailPrepNameStmt, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	_, err = stmt.ExecContext(ctx, user)
	if err != nil {
		return fmt.Errorf("[%s|UpdateEmailVerified] %s: %w", usrRN, errExecQuery, err)
	}

	return nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, tx *sqlx.Tx, user entities.UpdatePasswordUser) error {
	query := `UPDATE users SET password_hash = :password_hash, updated_at = :updated_at WHERE id = :id AND deleted_at IS NULL`

	// Prepare the named statement
	stmt, err := tx.PrepareNamedContext(ctx, query)
	if err != nil {
		return fmt.Errorf("[%s|UpdatePassword] %s: %w", usrRN, errFailPrepNameStmt, err)
	}
	defer dbHelpers.DbCloseNamedStmt(stmt)

	// Execute the query
	_, err = stmt.ExecContext(ctx, user)
	if err != nil {
		return fmt.Errorf("[%s|UpdatePassword] %s: %w", usrRN, errExecQuery, err)
	}

	return nil
}

func (r *userRepository) CheckByID(ctx context.Context, db *sqlx.DB, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)`

	var isExist bool
	err := db.GetContext(ctx, &isExist, query, id)
	if err != nil {
		return false, fmt.Errorf("[%s|CheckByID] %s: %w", usrRN, errExecQuery, err)
	}

	return isExist, nil
}

func (r *userRepository) CheckByUsernameHash(ctx context.Context, db *sqlx.DB, usernameHash string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username_hash = $1 AND deleted_at IS NULL)`

	var isExist bool
	err := db.GetContext(ctx, &isExist, query, usernameHash)
	if err != nil {
		return false, fmt.Errorf("[%s|CheckByUsernameHash] %s: %w", usrRN, errExecQuery, err)
	}

	return isExist, nil
}

func (r *userRepository) CheckByEmailHash(ctx context.Context, db *sqlx.DB, emailHash string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email_hash = $1 AND deleted_at IS NULL)`

	var isExist bool
	err := db.GetContext(ctx, &isExist, query, emailHash)
	if err != nil {
		return false, fmt.Errorf("[%s|CheckByEmailHash] %s: %w", usrRN, errExecQuery, err)
	}

	return isExist, nil
}

func (r *userRepository) FindOneByID(ctx context.Context, db *sqlx.DB, id string) (entities.User, error) {
	var user entities.User

	query := `SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL`

	err := db.GetContext(ctx, &user, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entities.User{}, dbErrors.DBErrNotFound
		}
		return entities.User{}, fmt.Errorf("[%s|FindOneByID] %s: %w", usrRN, errExecQuery, err)
	}

	return user, nil
}

func (r *userRepository) FindOneByEmailHash(ctx context.Context, db *sqlx.DB, emailHash string) (entities.User, error) {
	var user entities.User

	query := `SELECT * FROM users WHERE email_hash = $1 AND deleted_at IS NULL`

	err := db.GetContext(ctx, &user, query, emailHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entities.User{}, dbErrors.DBErrNotFound
		}
		return entities.User{}, fmt.Errorf("[%s|FindOneByEmailHash] %s: %w", usrRN, errExecQuery, err)
	}

	return user, nil
}

func NewUserRepository() UserRepository {
	return &userRepository{}
}
