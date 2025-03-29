# go-REST-Template
This is a Template for REST API in Go with JWT, Docker and a Database.

You can use it in two ways:
- **Authentication Microservice** (here)
- **Starting point for a backend** [click here](https://github.com/taekwondodev/go-REST-Template/tree/backend)

## Project Structure

```
go-REST-template/
├── backend/
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── repository/      # Handle Database Interaction
│   ├── service/         # Handle Controller Business Logic
│   ├── test/            # Unit Testing
│   ├── Dockerfile       
│   ├── go.mod           
│   ├── go.sum           
│   ├── main.go         
├── docker-compose.yml   
```

## Authentication with JWT

When an user sign in, the server respond with a message, an access token and a refresh token. The access token expires in 1 hour, the refresh token expires in 7 days.

If the access token is expired, there is the refresh endpoint to get a new access token.

## Database

I use postgreSQL for the project. At the start of your container instance will run the init script. It contains a table for the user with username and password as attribute.

## Docker

I use docker to manage dependencies. I divided the project into 3 containers: backend, test, postgres. So every container will run indipendently from the other two.

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
5. Open the terminal in the main directory and run the command:
   
   ```bash
   docker compose up -d
   ```

## Testing

To test the repository with automated test run the command in the main directory:

```bash
docker compose --profile run-tests up
```

## Acknowledgments

If you want to use this template, mention me in the README file or leave me a ⭐. Thank you!
