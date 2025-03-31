# Build
FROM golang:1.24.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

# Runtime
FROM alpine:3.18 AS runtime

WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8080

# Create a non-root user and group
RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot

# Switch to the non-root user
USER nonroot

CMD ["./main"]