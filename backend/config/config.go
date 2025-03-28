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
		log.Fatal("JWT_SECRET not defined")
	}

	DbURL = os.Getenv("POSTGRES_URL")
	if DbURL == "" {
		log.Fatal("POSTGRES_URL not defined")
	}
}
