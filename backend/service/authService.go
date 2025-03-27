package service

import (
	"backend/config"
	"backend/dto"
	"backend/repository"
)

type AuthService struct {
	repo repository.UserRepository
}

func NewAuthService(repo repository.UserRepository) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	checkReqIsValid(req)

	err := s.repo.CheckUsernameExist(req.Username)
	if err != nil {
		return nil, err
	}

	err = s.repo.SaveUser(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{Message: "Registrazione avvenuta con successo"}, nil
}

func (s *AuthService) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	checkReqIsValid(req)

	err := s.repo.CheckUserExist(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := config.GenerateJWT(req.Username)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:      "Login avvenuto con successo!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken}, nil
}

func (s *AuthService) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	claims, err := config.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := config.GenerateJWT(claims.Username)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:     "Token aggiornato con successo!",
		AccessToken: accessToken}, nil
}

func checkReqIsValid(req dto.AuthRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	return nil
}
