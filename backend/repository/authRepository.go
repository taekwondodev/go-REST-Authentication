package repository

import (
	"backend/models"
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	CheckUsernameExist(username string) error
	SaveUser(username string, password string, email string) error
	GetUserByCredentials(username string, password string) (*models.User, error)
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
		username,
		email,
		string(hashedPassword),
	)
	return err
}

func (r *UserRepositoryImpl) GetUserByCredentials(username string, password string) (*models.User, error) {
	var user models.User
	query := `
        SELECT id, username, email, password_hash, created_at, updated_at, is_active
        FROM user
        WHERE username = $1
    `

	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
