package test

import (
	"backend/controller"
	"backend/dto"
	"backend/errors"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const endpointRegisterString = "/register"
const endpointLoginString = "/login"
const endpointRefreshTokenString = "/refresh"
const badRequestString = "bad request\n"
const httpMethodNotAllowedString = "http Method not allowed\n"
const internalServerErrorString = "internal server error\n"
const invalidRefreshTokenString = "invalid-refresh-token"

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) HealthCheck() (*dto.HealthResponse, error) {
	args := m.Called()
	return args.Get(0).(*dto.HealthResponse), args.Error(1)
}

/****************************************************************/

func TestAuthControllerRegisterCorrect(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Register", req).Return(&dto.AuthResponse{Message: "Sign-Up successfully!"}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword", "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{"message":"Sign-Up successfully!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRegisterUserAlreadyExist(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Register", req).Return((*dto.AuthResponse)(nil), errors.ErrUserAlreadyExists)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "user already exists\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRegisterEmailAlreadyExist(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Register", req).Return((*dto.AuthResponse)(nil), errors.ErrEmailAlreadyExists)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "email already exists\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRegisterInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`invalid-json`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, badRequestString, w.Body.String())
}

func TestAuthControllerRegisterNotPOST(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, httpMethodNotAllowedString, w.Body.String())
}

func TestAuthControllerDbError(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Register", req).Return((*dto.AuthResponse)(nil), errors.ErrInternalServer)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, internalServerErrorString, w.Body.String())
	mockService.AssertExpectations(t)
}

/****************************************************************/

func TestAuthControllerLoginCorrect(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	mockService.On("Login", req).Return(&dto.AuthResponse{Message: "Login successful!"}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"Login successful!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerLoginInvalidCredentials(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	mockService.On("Login", req).Return((*dto.AuthResponse)(nil), errors.ErrInvalidCredentials)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "invalid credentials\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerLoginUserNotFound(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	mockService.On("Login", req).Return((*dto.AuthResponse)(nil), errors.ErrUserNotFound)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "user not found\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerLoginInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`invalid-json`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, badRequestString, w.Body.String())
}

func TestAuthControllerLoginNotPOST(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, httpMethodNotAllowedString, w.Body.String())
}

func TestAuthControllerLoginJWTError(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	mockService.On("Login", req).Return((*dto.AuthResponse)(nil), errors.ErrInternalServer)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, internalServerErrorString, w.Body.String())
	mockService.AssertExpectations(t)
}

/****************************************************************/

func TestAuthControllerRefreshTokenCorrect(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	mockService.On("Refresh", req).Return(&dto.AuthResponse{Message: "Token refreshed successfully!"}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"valid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"Token refreshed successfully!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRefreshTokenUnauthorized(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.RefreshTokenRequest{
		RefreshToken: invalidRefreshTokenString,
	}

	mockService.On("Refresh", req).Return((*dto.AuthResponse)(nil), errors.ErrInternalServer)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"invalid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, internalServerErrorString, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRefreshTokenInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`invalid-json`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, badRequestString, w.Body.String())
}

func TestAuthControllerRefreshTokenNotPOST(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"valid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, httpMethodNotAllowedString, w.Body.String())
}

func TestAuthControllerRefreshTokenExpired(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.RefreshTokenRequest{
		RefreshToken: invalidRefreshTokenString,
	}

	mockService.On("Refresh", req).Return((*dto.AuthResponse)(nil), jwt.ErrTokenExpired)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"invalid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "token is expired\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRefreshTokenNotValid(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.RefreshTokenRequest{
		RefreshToken: invalidRefreshTokenString,
	}

	mockService.On("Refresh", req).Return((*dto.AuthResponse)(nil), jwt.ErrSignatureInvalid)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"invalid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "signature is invalid\n", w.Body.String())
	mockService.AssertExpectations(t)
}
