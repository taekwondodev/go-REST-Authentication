package config

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var Db *sql.DB

func InitDB() {
	var err error

	Db, err = sql.Open("postgres", DbConnStr)
	if err != nil {
		log.Fatal("Error connection to database: ", err)
	}

	if err = Db.Ping(); err != nil {
		log.Fatal("Error ping to database:", err)
	}

	log.Println("Connection to database successfully!")
}

func CloseDB() {
	if Db == nil {
		return
	}

	Db.Close()
	log.Println("Connection to database closed!")
}
