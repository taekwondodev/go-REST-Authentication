# Use the official Golang image as the base image
FROM golang:1.24.1

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application code
COPY *.go ./

# Create a non-root user and group
RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot

# Switch to the non-root user
USER nonroot

# Run tests
CMD ["go", "test", "-v", "./..."]