# go-REST-Template
This is a Template for REST API with authentication already implemented in go.

## Architecture

![Image](https://github.com/user-attachments/assets/07687a2b-9003-4976-94ba-b5feaf0504fd)

## Authentication with JWT

The endpoints can be protected by the AuthMiddleware like for the refresh token endpoint. The AuthMiddleware check if the token received from the client is valid or not. The middleware is already implemented

## Database

I use postgreSQL for the project. It contains a table for the user.

## Usage

1. Download the zip project
2. Create a file ".env" in the main directory and insert the value of your instance:
   ```txt
   JWT_SECRET=default
   POSTGRES_URL=default
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=postgres
   ```
3. Open the terminal and run the code:
   ```bash
   docker compose up
   ```
   
