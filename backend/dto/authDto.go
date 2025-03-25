package dto

import "github.com/go-playground/validator/v10"

type AuthRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

func (a *AuthRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(a)
}

type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // Il token sarà presente solo in caso di successo
}
