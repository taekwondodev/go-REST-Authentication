package service

import (
	"backend/config"
	"backend/dto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CheckUsernameExist(username string) error {
	args := m.Called(username)
	return args.Error(0)
}

func (m *MockUserRepository) SaveUser(username string, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func (m *MockUserRepository) CheckUserExist(username string, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func TestAuthServiceRegister(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "password123",
	}

	mockRepo.On("CheckUsernameExist", req.Username).Return(nil)
	mockRepo.On("SaveUser", req.Username, req.Password).Return(nil)

	res, err := authService.Register(req)

	assert.NoError(t, err)
	assert.Equal(t, "Registrazione avvenuta con successo", res.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceLogin(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "password123",
	}

	mockRepo.On("CheckUserExist", req.Username, req.Password).Return(nil)
	config.JwtSecret = "testsecret"

	accessToken, refreshToken, _ := config.GenerateJWT(req.Username)
	res, err := authService.Login(req)

	assert.NoError(t, err)
	assert.Equal(t, "Login avvenuto con successo!", res.Message)
	assert.Equal(t, accessToken, res.AccessToken)
	assert.Equal(t, refreshToken, res.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceRefresh(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := NewAuthService(mockRepo)

	req := dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	config.JwtSecret = "testsecret"
	claims, _ := config.ValidateJWT(req.RefreshToken)
	accessToken, _, _ := config.GenerateJWT(claims.Username)

	res, err := authService.Refresh(req)

	assert.NoError(t, err)
	assert.Equal(t, "Token aggiornato con successo!", res.Message)
	assert.Equal(t, accessToken, res.AccessToken)
}
