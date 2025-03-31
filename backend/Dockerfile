# Build
FROM golang:1.24.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main .

# Runtime
FROM debian:bullseye-slim AS runtime

WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8080

# Create a non-root user and group
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# Switch to the non-root user
USER nonroot

CMD ["./main"]