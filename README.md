<div align="center">

# go-REST-Authentication

[![Go](https://img.shields.io/badge/Go-1.24.3+-00ADD8?logo=go)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Flyway](https://img.shields.io/badge/Flyway-CC0200?logo=flyway&logoColor=white)](https://flywaydb.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SonarCloud](https://img.shields.io/badge/SonarCloud-F3702A?logo=sonarcloud&logoColor=white)](https://sonarcloud.io/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/taekwondodev/go-REST-Authentication/docker-publish.yml?branch=master&logo=github)](https://github.com/taekwondodev/go-REST-Authentication/actions)
[![GitHub Tag](https://img.shields.io/github/v/tag/taekwondodev/go-REST-Authentication?logo=github&label=Latest%20Tag)](https://github.com/taekwondodev/go-REST-Authentication/tags)

Auth Microservice/Template for REST API in Go with JWT, Docker, PostgreSQL and End-to-End TLS Encryption

</div>

## API Endpoints

[![Open in Swagger Editor](https://img.shields.io/badge/Swagger-Editor-%23Clojure?style=for-the-badge&logo=swagger)](https://editor.swagger.io/?url=https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/master/backend/api/openapi.yaml)

- [Raw OpenAPI Spec](./backend/api/openapi.yaml)

## Features

- JWT Authentication (Access + Refresh tokens)
- PostgreSQL with TLS 1.3 (verify-full mode)
- Docker with internal network isolation
- Flyway migrations with certificate verification
- Unit testing
- Hardware-grade encryption for database connections
- Proxy and Logging Middleware

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)
- Install [Go](https://go.dev/dl/) (optional, only for local development)

## Usage

### Microservice

1. Download the docker-compose.yml and the configuration script files:

```bash
# Create a directory for the project
mkdir auth && cd auth

# Download the compose file
curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/master/docker-compose.yml

# Download the script file
curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/master/setup.sh
```

Or

Clone the project:

```bash
git clone https://github.com/taekwondodev/go-REST-Authentication.git
```

### Template

Clone the project:

```bash
git clone https://github.com/taekwondodev/go-REST-Authentication.git
```

### Configuration

Run the command in the main directory:

```bash
./setup.sh
```

### Deployment

Run the command in the main directory:

```bash
docker compose up -d
```

## Project Structure

```
go-REST-template/
├── app/
│   ├── api/             # Handle Server and Router Configs
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── customErrors/    # Handle Custom Errors
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── middleware/      # Middleware
│   ├── models/          # Database Models
│   ├── repository/      # Handle Database Interaction
│   ├── service/         # Handle Controller Business Logic
│   ├── Dockerfile
│   ├── go.mod
│   ├── go.sum
│   ├── main.go
├── migrations/          # SQL Script Migrations
├── postgres/            # SSL Certificates
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
