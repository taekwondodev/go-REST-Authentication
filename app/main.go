package main

import (
	"github.com/taekwondodev/go-REST-Authentication/api"
	"github.com/taekwondodev/go-REST-Authentication/config"
	"github.com/taekwondodev/go-REST-Authentication/controller"
	"github.com/taekwondodev/go-REST-Authentication/repository"
	"github.com/taekwondodev/go-REST-Authentication/service"
)

func main() {
	db := config.NewPostgres()
	db.InitDB()
	defer db.CloseDB()

	authRepo := repository.NewUserRepository(db.Db)
	authService := service.NewAuthService(authRepo, config.NewJWT())
	authController := controller.NewAuthController(authService)

	router := api.SetupRoutes(authController)
	server := api.NewServer(":80", router)

	server.StartWithGracefulShutdown()
}
