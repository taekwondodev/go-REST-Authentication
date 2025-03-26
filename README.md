# go-REST-Template
This is a Template for REST API with authentication already implemented in go and connected to a SQL database.

## Project Structure

```
go-REST-template/
├── backend/
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── middleware/      # Middleware
│   ├── repository/      # Handle Database Interaction
│   ├── service/         # Handle Controller Business Logic
│   ├── Dockerfile       
│   ├── go.mod           
│   ├── go.sum           
│   ├── main.go         
├── docker-compose.yml   
```

## Authentication with JWT

The endpoints can be protected by the AuthMiddleware like for the refresh token endpoint. The AuthMiddleware check if the token received from the client is valid or not. The middleware is already implemented

## Database

I use postgreSQL for the project. It contains a table for the user.

## Requirements

-Install [Go](https://go.dev/dl/)

-Install [Docker](https://docs.docker.com/engine/install/)

## Usage

1. Clone the project:
   ```bash
   git clone https://github.com/taekwondodev/go-REST-Template.git
   ```
3. Create a file ".env" in the main directory and insert the value of your instances:
   ```txt
   JWT_SECRET=default
   POSTGRES_URL=default
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=postgres
   ```
4. Open the terminal in the main directory and run the code:
   ```bash
   docker compose up -d
   ```
   
