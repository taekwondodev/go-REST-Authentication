package test

import (
	"backend/config"
	"backend/dto"
	"backend/service"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const errorTokenString = "errore nel generare il token"

type MockUserRepository struct {
	mock.Mock
}

type MockToken struct {
	mock.Mock
}

func (m *MockUserRepository) CheckUsernameExist(username string) error {
	args := m.Called(username)
	return args.Error(0)
}

func (m *MockUserRepository) CheckEmailExist(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockUserRepository) SaveUser(username string, password string, email string) error {
	args := m.Called(username, password, email)
	return args.Error(0)
}

func (m *MockUserRepository) CheckUserExist(username string, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func (m *MockToken) GenerateJWT(username string, email string) (string, string, error) {
	if username == "fail" {
		return "", "", errors.New(errorTokenString)
	}
	return "mockAccessToken", "mockRefreshToken", nil
}

func (m *MockToken) ValidateJWT(tokenString string) (*config.Claims, error) {
	if tokenString == "invalid" {
		return nil, errors.New("token non valido")
	}
	return &config.Claims{Username: "testuser"}, nil
}

/*******************************************************************************/

func TestAuthServiceRegisterCorrect(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "password123",
		Email:    emailString,
	}

	mockRepo.On("CheckUsernameExist", req.Username).Return(nil)
	mockRepo.On("CheckEmailExist", req.Email).Return(nil)
	mockRepo.On("SaveUser", req.Username, req.Password, req.Email).Return(nil)

	res, err := authService.Register(req)

	assert.NoError(t, err)
	assert.Equal(t, "Sign-Up successfully!", res.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceRegisterInvalidRequest(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "",
		Password: "",
		Email:    "",
	}

	res, err := authService.Register(req)

	assert.Nil(t, res)
	assert.Error(t, err)
}

func TestAuthServiceRegisterUserAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "existinguser",
		Password: "password123",
		Email:    emailString,
	}

	mockRepo.On("CheckUsernameExist", req.Username).Return(assert.AnError)

	res, err := authService.Register(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceRegisterEmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "existinguser",
		Password: "password123",
		Email:    emailString,
	}

	mockRepo.On("CheckUsernameExist", req.Username).Return(nil)
	mockRepo.On("CheckEmailExist", req.Email).Return(assert.AnError)

	res, err := authService.Register(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceRegisterSaveUserError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "newuser",
		Password: "password123",
		Email:    emailString,
	}

	mockRepo.On("CheckUsernameExist", req.Username).Return(nil)
	mockRepo.On("CheckEmailExist", req.Email).Return(nil)
	mockRepo.On("SaveUser", req.Username, req.Password, req.Email).Return(assert.AnError)

	res, err := authService.Register(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	mockRepo.AssertExpectations(t)
}

/*******************************************************************************/

func TestAuthServiceLoginCorrect(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "password123",
	}

	mockRepo.On("CheckUserExist", req.Username, req.Password).Return(nil)
	config.JwtSecret = "testsecret"

	accessToken, refreshToken, _ := mockToken.GenerateJWT(req.Username, req.Email)
	res, err := authService.Login(req)

	assert.NoError(t, err)
	assert.Equal(t, "Sign-In successfully!", res.Message)
	assert.Equal(t, accessToken, res.AccessToken)
	assert.Equal(t, refreshToken, res.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceLoginInvalidRequest(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "",
		Password: "",
	}

	res, err := authService.Login(req)

	assert.Nil(t, res)
	assert.Error(t, err)
}

func TestAuthServiceLoginUserNotExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "existinguser",
		Password: "password123",
	}

	mockRepo.On("CheckUserExist", req.Username, req.Password).Return(assert.AnError)

	res, err := authService.Login(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceLoginJWTError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo)

	req := dto.AuthRequest{
		Username: "fail",
		Password: "password123",
	}

	mockRepo.On("CheckUserExist", req.Username, req.Password).Return(nil)
	config.JwtSecret = "testsecret"

	mockToken.GenerateJWT(req.Username, req.Email)
	res, err := authService.Login(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, errorTokenString, err.Error())
	mockRepo.AssertExpectations(t)
}

/*******************************************************************************/

func TestAuthServiceRefreshCorrect(t *testing.T) {
	mockRepo := new(MockUserRepository)
	MockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo)

	req := dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	config.JwtSecret = "testsecret"
	claims, _ := MockToken.ValidateJWT(req.RefreshToken)
	accessToken, _, _ := MockToken.GenerateJWT(claims.Username, claims.Email)

	res, err := authService.Refresh(req)

	assert.NoError(t, err)
	assert.Equal(t, "Update token successfully!", res.Message)
	assert.Equal(t, accessToken, res.AccessToken)
	MockToken.AssertExpectations(t)
}

func TestAuthServiceRefreshInvalidRequest(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := service.NewAuthService(mockRepo)

	req := dto.RefreshTokenRequest{
		RefreshToken: "",
	}

	res, err := authService.Refresh(req)

	assert.Nil(t, res)
	assert.Error(t, err)
}

func TestAuthServiceRefreshInvalidToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo)

	req := dto.RefreshTokenRequest{
		RefreshToken: "invalid",
	}

	config.JwtSecret = "testsecret"

	mockToken.ValidateJWT(req.RefreshToken)
	res, err := authService.Refresh(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, "token non valido", err.Error())
	mockToken.AssertExpectations(t)
}

func TestAuthServiceRefreshErrorGenerate(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo)

	req := dto.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	}

	config.JwtSecret = "testsecret"

	claims, _ := mockToken.ValidateJWT(req.RefreshToken)
	claims.Username = "fail"
	mockToken.GenerateJWT(claims.Username, claims.Email)
	res, err := authService.Refresh(req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, errorTokenString, err.Error())
	mockToken.AssertExpectations(t)
}
