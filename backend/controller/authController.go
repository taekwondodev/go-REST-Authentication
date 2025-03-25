package controller

import (
	"backend/dto"
	"backend/service"
	"encoding/json"
	"net/http"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

func (c *AuthController) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.AuthRequest

	checkReqIsValid(w, r, req)

	res, err := c.authService.Register(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.AuthRequest

	checkReqIsValid(w, r, req)

	res, err := c.authService.Login(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func checkReqIsValid(w http.ResponseWriter, r *http.Request, req dto.AuthRequest) {
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Request non valida", http.StatusBadRequest)
		return
	}
}
