package test

import (
	"backend/controller"
	"backend/dto"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const endpointRegisterString = "/register"
const endpointLoginString = "/login"
const endpointRefreshTokenString = "/refresh"
const httpMethodNotAllowedString = "Http Method not allowed\n"

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
	assert.JSONEq(t, `{"Message":"Sign-Up successfully!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRegisterConflict(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Register", req).Return(nil, errors.New("user already exists"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "user already exists\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRegisterInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRegisterString, bytes.NewBufferString(`invalid-json`))

	authController.Register(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "Bad request\n", w.Body.String())
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

/****************************************************************/

func TestAuthControllerLoginCorrect(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Login", req).Return(&dto.AuthResponse{Message: "Login successful!"}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword",  "email":"example@domain.com"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"Message":"Login successful!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerLoginConflict(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	mockService.On("Login", req).Return(nil, errors.New("invalid credentials"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword"}, "email":"example@domain.com"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "invalid credentials\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerLoginInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointLoginString, bytes.NewBufferString(`invalid-json`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "Bad request\n", w.Body.String())
}

func TestAuthControllerLoginNotPOST(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, endpointLoginString, bytes.NewBufferString(`{"username":"testuser","password":"testpassword", "email":"example@domain.com"}`))

	authController.Login(w, r)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, httpMethodNotAllowedString, w.Body.String())
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
	assert.JSONEq(t, `{"Message":"Token refreshed successfully!"}`, w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRefreshTokenUnauthorized(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	req := dto.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	}

	mockService.On("Refresh", req).Return(nil, errors.New("invalid refresh token"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`{"refreshToken":"invalid-refresh-token"}`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "invalid refresh token\n", w.Body.String())
	mockService.AssertExpectations(t)
}

func TestAuthControllerRefreshTokenInvalidRequest(t *testing.T) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, endpointRefreshTokenString, bytes.NewBufferString(`invalid-json`))

	authController.Refresh(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "Request non valida\n", w.Body.String())
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
