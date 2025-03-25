package service

import (
	"backend/config"
	"backend/dto"
	"backend/repository"
	"errors"
)

type AuthService struct {
	repo *repository.UserRepository
}

func NewAuthService(repo *repository.UserRepository) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	checkReqIsValid(req)

	exists := s.repo.CheckUserExist(req.Username)
	if exists {
		return nil, errors.New("username già in uso")
	}

	err := s.repo.SaveUser(req.Username, req.Password)
	if err != nil {
		return nil, errors.New("errore salvataggio utente")
	}

	return &dto.AuthResponse{Message: "Registrazione avvenuta con successo"}, nil
}

func (s *AuthService) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	checkReqIsValid(req)

	exists := s.repo.CheckUserExist(req.Username)
	if !exists {
		return nil, errors.New("username non esiste")
	}

	token, err := config.GenerateJWT(req.Username)
	if err != nil {
		return nil, errors.New("errore generazione token")
	}

	return &dto.AuthResponse{Message: "Login avvenuto con successo!", Token: token}, nil
}

func checkReqIsValid(req dto.AuthRequest) error {
	if err := req.Validate(); err != nil {
		return errors.New("username e password sono obbligatori")
	}
	return nil
}
