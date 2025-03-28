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
	if err := checkReqIsValid(req); err != nil {
		return nil, err
	}

	err := s.repo.CheckUsernameExist(req.Username)
	if err != nil {
		return nil, err
	}

	err = s.repo.SaveUser(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{Message: "Sign-Up successfully!"}, nil
}

func (s *AuthService) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := checkReqIsValid(req); err != nil {
		return nil, err
	}

	err := s.repo.CheckUserExist(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	jwt := config.JWT{}
	accessToken, refreshToken, err := jwt.GenerateJWT(req.Username)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:      "Sign-In successfully!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken}, nil
}

func (s *AuthService) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	jwt := config.JWT{}
	claims, err := jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := jwt.GenerateJWT(claims.Username)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:     "Update token successfully!",
		AccessToken: accessToken}, nil
}

func checkReqIsValid(req dto.AuthRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	return nil
}
