package service

import (
	"backend/config"
	customerrors "backend/customErrors"
	"backend/dto"
	"backend/repository"
	"context"

	"github.com/google/uuid"
)

type AuthService interface {
	Register(req dto.AuthRequest) (*dto.AuthResponse, error)
	Login(req dto.AuthRequest) (*dto.AuthResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error)
	HealthCheck(ctx context.Context) (*dto.HealthResponse, error)
}

type AuthServiceImpl struct {
	repo repository.UserRepository
	jwt  config.Token
}

func NewAuthService(repo repository.UserRepository, jwt config.Token) AuthService {
	return &AuthServiceImpl{repo: repo, jwt: jwt}
}

func (s *AuthServiceImpl) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	if err := s.repo.CheckUserExists(req.Username, req.Email); err != nil {
		return nil, err
	}

	sub, err := s.repo.SaveUser(req.Username, req.Password, req.Email, req.Role)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message: "Sign-Up successfully!",
		Sub:     sub.String(),
	}, nil
}

func (s *AuthServiceImpl) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	user, err := s.repo.GetUserByCredentials(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.jwt.GenerateJWT(user.Username, user.Email, user.Role, user.ID)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:      "Sign-In successfully!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthServiceImpl) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Email, claims.Role, uuid.MustParse(claims.Subject))
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:     "Update token successfully!",
		AccessToken: accessToken,
	}, nil
}

func (s *AuthServiceImpl) HealthCheck(ctx context.Context) (*dto.HealthResponse, error) {
	if err := s.repo.HealthCheck(ctx); err != nil {
		return nil, err
	}

	return &dto.HealthResponse{
		Status:   "OK",
		Database: "Connected",
		SslMode:  "verify-full",
	}, nil
}
