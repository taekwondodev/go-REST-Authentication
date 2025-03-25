package config

import (
	"log"
	"os"
)

var JwtSecret string
var DbURL string

func LoadEnv() {
	JwtSecret = os.Getenv("JWT_SECRET")
	if JwtSecret == "" {
		log.Fatal("JWT_SECRET non definito")
	}

	DbURL = os.Getenv("DATABASE_URL")
	if DbURL == "" {
		log.Fatal("DATABASE_URL non definito")
	}
}
