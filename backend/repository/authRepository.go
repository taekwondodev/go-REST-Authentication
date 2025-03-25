package repository

import "database/sql"

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CheckUserExist(username string) bool {
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM User WHERE username=$1)", username).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (r *UserRepository) SaveUser(username, password string) error {
	_, err := r.db.Exec("INSERT INTO User (username, password) VALUES ($1, $2)", username, password)
	return err
}
