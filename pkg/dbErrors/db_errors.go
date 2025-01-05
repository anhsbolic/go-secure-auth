package dbErrors

import "errors"

var (
	DBErrConflict = errors.New("db error | conflict")
	DBErrNotFound = errors.New("db error | not found")
)
