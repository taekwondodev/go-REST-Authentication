package controller

import (
	"backend/dto"
	"backend/errors"
	"backend/service"
	"encoding/json"
	"net/http"
)

type AuthController struct {
	authService service.AuthService
}

func NewAuthController(authService service.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

func (c *AuthController) Register(w http.ResponseWriter, r *http.Request) {
	if !checkPostMethod(w, r) {
		return
	}

	var req dto.AuthRequest

	if !checkReqIsValid(w, r, &req) {
		return
	}

	res, err := c.authService.Register(req)
	if err != nil {
		errors.HandleHttpError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	if !checkPostMethod(w, r) {
		return
	}

	var req dto.AuthRequest

	if !checkReqIsValid(w, r, &req) {
		return
	}

	res, err := c.authService.Login(req)
	if err != nil {
		errors.HandleHttpError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func (c *AuthController) Refresh(w http.ResponseWriter, r *http.Request) {
	if !checkPostMethod(w, r) {
		return
	}

	var req dto.RefreshTokenRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		errors.HandleHttpError(w, errors.ErrBadRequest)
		return
	}

	res, err := c.authService.Refresh(req)
	if err != nil {
		errors.HandleHttpError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func (c *AuthController) HealthCheck(w http.ResponseWriter, r *http.Request) {
	res, err := c.authService.HealthCheck()
	if err != nil {
		errors.HandleHttpError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func checkPostMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		errors.HandleHttpError(w, errors.ErrHttpMethodNotAllowed)
		return false
	}

	return true
}

func checkReqIsValid(w http.ResponseWriter, r *http.Request, req *dto.AuthRequest) bool {
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		errors.HandleHttpError(w, errors.ErrBadRequest)
		return false
	}

	return true
}
