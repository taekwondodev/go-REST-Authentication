# go-REST-Template
This is a Template for REST API in Go with JWT, Docker and a Database.

You can use it in two ways:
- **Authentication Microservice**
- **Starting point for a backend**

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

I use postgreSQL for the project. At the start of your container instance will run the init script. It contains a table for the user.

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)

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
5. Open the terminal in the main directory and run the code:
   
   ```bash
   docker compose up -d
   ```

## Contributions

If you find any bugs or have suggestions for improvements, feel free to open an issue or submit a pull request!

## Acknowledgments

If you want to use this template, mention me in the README file or leave me a ⭐. Thank you!
