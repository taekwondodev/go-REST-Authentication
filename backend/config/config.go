package config

import (
	"fmt"
	"log"
	"os"
)

var JwtSecret string
var DbURL string
var DbConnStr string

func LoadEnv() {
	JwtSecret = os.Getenv("JWT_SECRET")
	if JwtSecret == "" {
		log.Fatal("JWT_SECRET not defined")
	}

	DbConnStr = fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DB_SSLMODE"),
	)
	if DbConnStr == "" {
		log.Fatal("DB connection string not defined")
	}
}
