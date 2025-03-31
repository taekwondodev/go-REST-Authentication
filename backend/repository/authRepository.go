package repository

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	CheckUsernameExist(username string) error
	SaveUser(username string, password string, email string) error
	CheckUserExist(username string, password string) error
	CheckEmailExist(email string) error
}

type UserRepositoryImpl struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &UserRepositoryImpl{db: db}
}

func (r *UserRepositoryImpl) CheckUsernameExist(username string) error {
	var exists bool
	return r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM user WHERE username=$1)", username).Scan(&exists)
}

func (r *UserRepositoryImpl) CheckEmailExist(email string) error {
	var exists bool
	return r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM user WHERE email=$1)", email).Scan(&exists)
}

func (r *UserRepositoryImpl) SaveUser(username string, password string, email string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		"INSERT INTO user (username, email, password_hash) VALUES ($1, $2, $3)",
		username, email, string(hashedPassword))
	return err
}

func (r *UserRepositoryImpl) CheckUserExist(username string, password string) error {
	var hashedPassword string

	err := r.db.QueryRow("SELECT password_hash FROM user WHERE username=$1", username).Scan(&hashedPassword)
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
