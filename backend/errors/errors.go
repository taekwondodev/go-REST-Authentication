package errors

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
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

func HandleHttpError(w http.ResponseWriter, err error) {
	switch err {
	case ErrUserAlreadyExists, ErrEmailAlreadyExists:
		http.Error(w, err.Error(), http.StatusConflict)
	case ErrInvalidCredentials, jwt.ErrSignatureInvalid, jwt.ErrTokenExpired:
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case ErrUserNotFound:
		http.Error(w, err.Error(), http.StatusNotFound)
	case ErrHttpMethodNotAllowed:
		http.Error(w, err.Error(), http.StatusMethodNotAllowed)
	case ErrBadRequest:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case ErrDbUnreacheable:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case ErrDbSSLHandshakeFailed:
		http.Error(w, err.Error(), http.StatusBadGateway)
	case ErrDbTimeout:
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
