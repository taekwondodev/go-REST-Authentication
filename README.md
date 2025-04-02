# go-REST-Authentication
This is a Template for REST API in Go with JWT, Docker and a Database.

You can use it in two ways:
- **Authentication Microservice**
- **Starting point for a backend**

## API Endpoints

### 1. **Sign Up**
- **Endpoint:** `POST /register`
- **Request Body:**
  ```json
  {
    "username": "example_user",
    "email": "example@example.com",
    "password": "password123"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Sign-Up successfully!"
  }
  ```

### 2. **Sign In**
- **Endpoint:** `POST /login`
- **Request Body:**
  ```json
  {
    "username": "example_user",
    "password": "password123"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Sign-In successfully!",
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "dXNlcm5hbWU6ZXhhbXBsZV91c2Vy..."
  }
  ```

  ### 3. **Refresh Token**
- **Endpoint:** `POST /refresh`
- **Request Body:**
  ```json
  {
    "refreshToken": "dXNlcm5hbWU6ZXhhbXBsZV91c2Vy..."
  }
  ```
- **Response:**
  ```json
  {
    "message": "Update token successfully!",
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

## Project Structure

```
go-REST-template/
├── backend/
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── errors/          # Handle Global Errors
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

## JWT

When an user sign in, the server respond with a message, an access token and a refresh token. The access token expires in 1 hour, the refresh token expires in 7 days.

If the access token is expired, there is the refresh endpoint to get a new access token.

## Database

I use postgreSQL for the project. At the start of your container instance will run the migration script. It contains a table for the users.

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
2. Open the terminal and create the Certificates for SSL mode for postgreSQL:

   ```bash
   mkdir -p postgres/ssl && cd postgres/ssl
   openssl req -new -x509 -days 365 -nodes -text -out server.crt -keyout server.key -subj "/CN=postgres"
   chmod 600 server.key
   ```
3. Open the terminal and run the command to generate JWT_SECRET and copy it:

   ```bash
   openssl rand -hex 32
   ```
3. Create a file ".env" in the main directory and insert the value of your instances:
   
   ```txt
   JWT_SECRET=default
   DB_HOST=postgres                                        
   DB_PORT=5432
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=go                                           
   POSTGRES_URL=jdbc:postgresql://postgres:5432/go?sslmode=require
   DB_SSLMODE=require
   ```
4. Open the terminal in the main directory and run the command:
   
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
