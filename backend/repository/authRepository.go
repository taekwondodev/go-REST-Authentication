package repository

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	CheckUsernameExist(username string) error
	SaveUser(username string, password string) error
	CheckUserExist(username string, password string) error
}

type UserRepositoryImpl struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &UserRepositoryImpl{db: db}
}

func (r *UserRepositoryImpl) CheckUsernameExist(username string) error {
	var exists bool
	return r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM User WHERE username=$1)", username).Scan(&exists)
}

func (r *UserRepositoryImpl) SaveUser(username string, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("INSERT INTO User (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	return err
}

func (r *UserRepositoryImpl) CheckUserExist(username string, password string) error {
	var hashedPassword string

	err := r.db.QueryRow("SELECT password FROM User WHERE username=$1", username).Scan(&hashedPassword)
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
