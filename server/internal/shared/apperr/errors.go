package apperr

import "errors"

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrInvalidConfig  = errors.New("invalid config")
	ErrNotFound       = errors.New("not found")
)
