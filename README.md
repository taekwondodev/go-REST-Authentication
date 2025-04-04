# go-REST-Authentication
[![Go](https://img.shields.io/badge/Go-1.24.1+-00ADD8?logo=go)](https://golang.org)

Auth Microservice/Template for REST API in Go with JWT, Docker and PostgreSQL.

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

  ### 4. **Health Check**
- **Endpoint:** `GET /healthz`
- **Response:**
  ```json
  {
    "status": "OK"
  }
  ```

## Features
- JWT Authentication (Access + Refresh tokens)
- PostgreSQL database integration
- Docker-ready configuration
- Automated migrations with Flyway
- Unit testing setup
- SSL-secured PostgreSQL connection

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)
- Install [Go](https://go.dev/dl/) (optional, only for local development)

## Usage

### Microservice

1. Download the docker-compose.yml and the migration script files:
  ```bash
  # Create a directory for the project
  mkdir auth && cd auth

  # Download the compose file
  curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/microservice/docker-compose.yml

  # Create the migration directory
  mkdir -p migrations && cd migrations

  # Download the script sql file
  curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/microservice/migrations/V1__Create_User_table.sql
  ```
  Or

  Clone the project:
   
  ```bash
  git clone https://github.com/taekwondodev/go-REST-Template.git
  ```

### Template

  Clone the project:

  ```bash
  git clone https://github.com/taekwondodev/go-REST-Template.git
  ```

### Configuration
1. Open the terminal in the main directory and create the Certificates for SSL mode for postgreSQL:

  ```bash
  mkdir -p postgres/ssl && cd postgres/ssl
  openssl req -new -x509 -days 3650 -nodes -text -out server.crt -keyout server.key -subj "/CN=postgres"
  chmod 600 server.key
  cd ../..
  ```
2. Run the command to generate JWT_SECRET and copy it:

  ```bash
  openssl rand -hex 32
  ```
3. Create a file ".env" in the main directory and insert the value of your instances:
   
  ```ini
  # Authentication
  JWT_SECRET=your_generated_hex_here  # Required for token signing

  # Database Configuration

  DB_HOST=postgres                    # Container name (don't change for compose)
  DB_PORT=5432                        # Default PostgreSQL port
  POSTGRES_USER=your_db_user          # Database username
  POSTGRES_PASSWORD=your_db_password  # Database password
  POSTGRES_DB=your_db_name            # Database name

  # SSL Settings
  DB_SSLMODE=require                  
  POSTGRES_URL=jdbc:postgresql://${DB_HOST}:${DB_PORT}/${POSTGRES_DB}?sslmode=${DB_SSLMODE}
  ```

### Deployment

Run the command in the main directory:
   
  ```bash
  docker compose up -d
  ```

## Project Structure

```
go-REST-template/
├── backend/
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── errors/          # Handle Global Errors
│   ├── middleware/      # Middleware
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

**Note**: If you run this repo as a Microservice you can skip this.

## Testing

To test the repository with automated test run the command in the main directory:

```bash
# Build the image
docker build -f Dockerfile.test -t myapp-test .

# Execute
docker run --rm myapp-test
```

**Note**: If you run this repo as a Microservice you can skip this.

## Acknowledgments

If you want to use this template, mention me in the README file or leave me a ⭐. Thank you!
