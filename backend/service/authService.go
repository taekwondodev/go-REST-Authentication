package service

import (
	"backend/config"
	"backend/dto"
	"backend/errors"
	"backend/repository"
	"context"
	"strings"
	"time"
)

type AuthService interface {
	Register(req dto.AuthRequest) (*dto.AuthResponse, error)
	Login(req dto.AuthRequest) (*dto.AuthResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error)
	HealthCheck() (*dto.HealthResponse, error)
}

type AuthServiceImpl struct {
	repo repository.UserRepository
	jwt  config.Token
}

func NewAuthService(repo repository.UserRepository, jwt config.Token) AuthService {
	return &AuthServiceImpl{repo: repo, jwt: jwt}
}

func (s *AuthServiceImpl) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := checkReqIsValid(req); err != nil {
		return nil, errors.ErrBadRequest
	}

	if err := s.repo.CheckEmailExist(req.Email); err != nil {
		return nil, errors.ErrEmailAlreadyExists
	}

	if err := s.repo.CheckUsernameExist(req.Username); err != nil {
		return nil, errors.ErrUserAlreadyExists
	}

	if err := s.repo.SaveUser(req.Username, req.Password, req.Email); err != nil {
		return nil, err
	}

	return &dto.AuthResponse{Message: "Sign-Up successfully!"}, nil
}

func (s *AuthServiceImpl) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := checkReqIsValid(req); err != nil {
		return nil, errors.ErrBadRequest
	}

	user, err := s.repo.GetUserByCredentials(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.jwt.GenerateJWT(user.Username, user.Email)
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
		return nil, errors.ErrBadRequest
	}

	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Email)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:     "Update token successfully!",
		AccessToken: accessToken,
	}, nil
}

func (s *AuthServiceImpl) HealthCheck() (*dto.HealthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := config.Db.PingContext(ctx); err != nil {
		if isSSLerror(err) {
			return nil, errors.ErrDbSSLHandshakeFailed
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, errors.ErrDbTimeout
		}
		return nil, errors.ErrDbUnreacheable
	}

	return &dto.HealthResponse{
		Status:   "OK",
		Database: "Connected",
		SslMode:  "verify-full",
	}, nil
}

func checkReqIsValid(req dto.AuthRequest) error {
	return req.Validate()
}

func isSSLerror(err error) bool {
	return strings.Contains(err.Error(), "SSL") ||
		strings.Contains(err.Error(), "certificate") ||
		strings.Contains(err.Error(), "TLS")
}
