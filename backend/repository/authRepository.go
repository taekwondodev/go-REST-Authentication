package repository

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CheckUsernameExist(username string) error {
	var exists bool
	return r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM User WHERE username=$1)", username).Scan(&exists)
}

func (r *UserRepository) SaveUser(username string, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("INSERT INTO User (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	return err
}

func (r *UserRepository) CheckUserExist(username string, password string) error {
	var hashedPassword string

	err := r.db.QueryRow("SELECT password FROM User WHERE username=$1", username).Scan(&hashedPassword)
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
