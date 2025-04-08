package middleware

import (
	customerrors "backend/customErrors"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func ErrorHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			handleHttpError(w, err)
		}
	}
}

func handleHttpError(w http.ResponseWriter, err error) {
	status := httpStatusFromError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	res := &Error{
		Code:    status,
		Message: err.Error(),
	}

	json.NewEncoder(w).Encode(res)
}

func httpStatusFromError(err error) int {
	switch {
	case errors.Is(err, customerrors.ErrUserAlreadyExists),
		errors.Is(err, customerrors.ErrEmailAlreadyExists):
		return http.StatusConflict

	case errors.Is(err, customerrors.ErrInvalidCredentials),
		errors.Is(err, jwt.ErrSignatureInvalid),
		errors.Is(err, jwt.ErrTokenExpired):
		return http.StatusUnauthorized

	case errors.Is(err, customerrors.ErrUserNotFound):
		return http.StatusNotFound

	case errors.Is(err, customerrors.ErrHttpMethodNotAllowed):
		return http.StatusMethodNotAllowed

	case errors.Is(err, customerrors.ErrBadRequest):
		return http.StatusBadRequest

	case errors.Is(err, customerrors.ErrDbUnreacheable):
		return http.StatusServiceUnavailable

	case errors.Is(err, customerrors.ErrDbSSLHandshakeFailed):
		return http.StatusBadGateway

	case errors.Is(err, customerrors.ErrDbTimeout):
		return http.StatusGatewayTimeout

	default:
		return http.StatusInternalServerError
	}
}
