package dbHelpers

import (
	"database/sql"
	"github.com/anhsbolic/go-secure-auth/pkg/logging"
	"github.com/jmoiron/sqlx"
	"time"
)

// DbCloseNamedStmt safely closes the provided statement and logs any error.
func DbCloseNamedStmt(stmt *sqlx.NamedStmt) {
	if stmt != nil {
		if err := stmt.Close(); err != nil {
			logging.Logger().Errorf("Failed to close statement: %v", err)
		}
	}
}

// DbCloseRows safely closes the provided rows and logs any error.
func DbCloseRows(rows *sqlx.Rows) {
	if rows != nil {
		if err := rows.Close(); err != nil {
			logging.Logger().Errorf("Failed to close rows: %v", err)
		}
	}
}

// DbCommitOrRollback Helper function to commit or rollback transaction depending on transaction error
func DbCommitOrRollback(tx *sqlx.Tx, err *error) {
	if r := recover(); r != nil {
		logging.Logger().Errorf("Rolling back transaction due to panic: %v", r)
		_ = tx.Rollback()
		panic(r)
	} else if *err != nil {
		logging.Logger().Errorf("Rolling back transaction due to error: %v", *err)
		_ = tx.Rollback()
	} else {
		if err := tx.Commit(); err != nil {
			logging.Logger().Errorf("Failed to commit transaction: %v", err)
			_ = tx.Rollback()
		}
	}
}

// DbRollbackOnPanic Helper function to rollback transaction on panic
func DbRollbackOnPanic(tx *sqlx.Tx) {
	if r := recover(); r != nil {
		_ = tx.Rollback()
		panic(r)
	}
}

// NullStringToPointer Helper function to convert sql.NullString to *string
func NullStringToPointer(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

// NullTimeToPointer Helper function to convert sql.NullTime to *time.Time
func NullTimeToPointer(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

// NullTimeToTime Helper function to convert sql.NullTime to time.Time with a fallback
func NullTimeToTime(nt sql.NullTime) time.Time {
	if nt.Valid {
		return nt.Time
	}
	return time.Time{} // Or use a zero value or specific fallback
}
