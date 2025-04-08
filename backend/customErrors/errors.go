package customerrors

import (
	"errors"
)

var (
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrEmailAlreadyExists   = errors.New("email already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrUserNotFound         = errors.New("user not found")
	ErrHttpMethodNotAllowed = errors.New("http Method not allowed")
	ErrBadRequest           = errors.New("bad request")
	ErrInternalServer       = errors.New("internal server error")
	ErrDbUnreacheable       = errors.New("database unreachable")
	ErrDbSSLHandshakeFailed = errors.New("database ssl handshake failed")
	ErrDbTimeout            = errors.New("database timeout")
)
