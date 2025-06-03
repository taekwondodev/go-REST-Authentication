package controller

import (
	"encoding/json"
	"net/http"

	customerrors "github.com/taekwondodev/go-REST-Authentication/customErrors"
	"github.com/taekwondodev/go-REST-Authentication/dto"
	"github.com/taekwondodev/go-REST-Authentication/service"
)

type AuthController struct {
	authService service.AuthService
}

func NewAuthController(authService service.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

func (c *AuthController) Register(w http.ResponseWriter, r *http.Request) error {
	var req dto.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.Register(req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusCreated, res)
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) error {
	var req dto.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.Login(req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}

func (c *AuthController) Refresh(w http.ResponseWriter, r *http.Request) error {
	var req dto.RefreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return customerrors.ErrBadRequest
	}

	res, err := c.authService.Refresh(req)
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}

func (c *AuthController) HealthCheck(w http.ResponseWriter, r *http.Request) error {
	res, err := c.authService.HealthCheck(r.Context())
	if err != nil {
		return err
	}

	return c.respond(w, http.StatusOK, res)
}

func (c *AuthController) respond(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
