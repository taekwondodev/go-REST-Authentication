package test

import (
	"backend/repository"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const existQuery = "SELECT EXISTS"
const selectPasswordQuery = "SELECT password_hash FROM User WHERE username=\\$1"
const emailString = "example@domain.com"

func TestCheckUsernameExistCorrect(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	rows := sqlmock.NewRows([]string{"exists"}).AddRow(true)
	mock.ExpectQuery(existQuery).WithArgs(username).WillReturnRows(rows)

	err := repo.CheckUsernameExist(username)
	assert.NoError(t, err)
}

func TestCheckUsernameExistNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	mock.ExpectQuery(existQuery).WithArgs(username).WillReturnError(sql.ErrNoRows)

	err := repo.CheckUsernameExist(username)
	assert.Error(t, err)
}

func TestCheckUsernameExistDbError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	mock.ExpectQuery(existQuery).WithArgs(username).WillReturnError(sql.ErrConnDone)

	err := repo.CheckUsernameExist(username)
	assert.Error(t, err)
}

/****************************************************************/

func TestCheckEmailExistCorrect(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	rows := sqlmock.NewRows([]string{"exists"}).AddRow(true)
	mock.ExpectQuery(existQuery).WithArgs(emailString).WillReturnRows(rows)

	err := repo.CheckEmailExist(emailString)
	assert.NoError(t, err)
}

func TestCheckEmailExistNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	mock.ExpectQuery(existQuery).WithArgs(emailString).WillReturnError(sql.ErrNoRows)

	err := repo.CheckEmailExist(emailString)
	assert.Error(t, err)
}

func TestCheckEmailExistDbError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	mock.ExpectQuery(existQuery).WithArgs(emailString).WillReturnError(sql.ErrConnDone)

	err := repo.CheckEmailExist(emailString)
	assert.Error(t, err)
}

/****************************************************************/

func TestSaveUserCorrect(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	password := "password123"
	mock.ExpectExec("INSERT INTO User").WithArgs(username, password, emailString).WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.SaveUser(username, password, emailString)
	assert.NoError(t, err)
}

func TestSaveUserPasswordHashingError(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	invalidPassword := string(make([]byte, 0))

	err := repo.SaveUser(username, invalidPassword, emailString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bcrypt")
}

func TestSaveUserDbError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	password := "password123"
	mock.ExpectExec("INSERT INTO User").WithArgs(username, password, emailString).WillReturnError(sql.ErrConnDone)

	err := repo.SaveUser(username, password, emailString)
	assert.Error(t, err)
}

/****************************************************************/

func TestCheckUserExistCorrect(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	mock.ExpectQuery(selectPasswordQuery).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows([]string{"password_hash"}).AddRow(string(hashedPassword)))

	err := repo.CheckUserExist(username, password)
	assert.NoError(t, err)
}

func TestCheckUserExistIncorrectPassword(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	password := "password123"
	wrongPassword := "wrongpassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	mock.ExpectQuery(selectPasswordQuery).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows([]string{"password_hash"}).AddRow(string(hashedPassword)))

	err := repo.CheckUserExist(username, wrongPassword)
	assert.Error(t, err)
}

func TestCheckUserExistUserNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "nonexistentuser"
	password := "password123"

	mock.ExpectQuery(selectPasswordQuery).
		WithArgs(username).
		WillReturnError(sql.ErrNoRows)

	err := repo.CheckUserExist(username, password)
	assert.Error(t, err)
}

func TestCheckUserExistDbError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	repo := repository.NewUserRepository(db)

	username := "testuser"
	password := "password123"

	mock.ExpectQuery(selectPasswordQuery).
		WithArgs(username).
		WillReturnError(sql.ErrConnDone)

	err := repo.CheckUserExist(username, password)
	assert.Error(t, err)
}
