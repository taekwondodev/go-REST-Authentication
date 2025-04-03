# Build
FROM --platform=$BUILDPLATFORM golang:1.24.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o main .

# Runtime
FROM --platform=$TARGETPLATFORM debian:bookworm-slim AS runtime

WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8080

# Create a non-root user and group
RUN groupadd -r nonroot && \
    useradd --no-log-init -r -g nonroot nonroot && \
    chown -R nonroot:nonroot /app

# Switch to the non-root user
USER nonroot

CMD ["./main"]