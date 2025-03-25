# go-REST-Template
This is a Template for REST API with authentication already implemented in go.

## Architecture

![Image](https://github.com/user-attachments/assets/1e62b6f7-371c-4dba-9f8c-b65c5ef8ecfc)

## Authentication with JWT

The endpoints can be protected by the AuthMiddleware like for the refresh token endpoint. The AuthMiddleware check if the token received from the client is valid or not. The middleware is already implemented

## Database

I use postgreSQL for the project. It contains a table for the user.

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
   
