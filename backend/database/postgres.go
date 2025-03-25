package database

import (
	"backend/config"
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var Db *sql.DB

func InitDB() {
	var err error

	Db, err = sql.Open("postgres", config.DbURL)
	if err != nil {
		log.Fatal("Errore connessione al database: ", err)
	}

	if err = Db.Ping(); err != nil {
		log.Fatal("Errore nel ping del database:", err)
	}

	log.Println("Connessione al database riuscita!")
}

func CloseDB() {
	if Db == nil {
		return
	}

	Db.Close()
	log.Println("Connessione al database chiusa!")
}
