package dto

import "github.com/go-playground/validator/v10"

type AuthRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
	Email    string `json:"email" validate:"required,email"`
}

func (a *AuthRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(a)
}

type AuthResponse struct {
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken,omitzero"`
	RefreshToken string `json:"refreshToken,omitzero"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

func (r *RefreshTokenRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
