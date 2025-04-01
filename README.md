# go-REST-Authentication
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
│   ├── models/          # Database Models
│   ├── repository/      # Handle Database Interaction
│   ├── service/         # Handle Controller Business Logic
│   ├── Dockerfile       
│   ├── go.mod           
│   ├── go.sum           
│   ├── main.go  
├── test/                # Unit Testing    
├── Dockerfile.test        
├── docker-compose.yml   
```

## Authentication with JWT

When an user sign in, the server respond with a message, an access token and a refresh token. The access token expires in 1 hour, the refresh token expires in 7 days.

If the access token is expired, there is the refresh endpoint to get a new access token.

## Database

I use postgreSQL for the project. At the start of your container instance will run the migration script. It contains a table for the user.

## Docker

I use docker to manage dependencies. I divided the project into 4 containers: backend, test, postgres, flyway. So every container will run indipendently from the others.

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)
- Install [Go](https://go.dev/dl/) (optional, only for local development)

## Usage

1. Clone the project:
   
   ```bash
   git clone https://github.com/taekwondodev/go-REST-Template.git
   ```
2. Create a file ".env" in the main directory and insert the value of your instances:
   
   ```txt
   JWT_SECRET=default 
   DB_HOST=postgres                                         # Service Name in Docker Compose
   DB_PORT=5432
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=go                                           # Database Name
   POSTGRES_URL=jdbc:postgresql://postgres:5432/go
   DB_SSLMODE=disable
   ```
3. Open the terminal in the main directory and run the command:
   
   ```bash
   docker compose up -d
   ```

## Testing

To test the repository with automated test run the command in the main directory:

```bash
docker compose up test
```

## Acknowledgments

If you want to use this template, mention me in the README file or leave me a ⭐. Thank you!
