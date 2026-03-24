FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o api-server

# Final stage: use alpine as base
FROM alpine:latest

# Install dependencies
RUN apk --no-cache add ca-certificates bash

WORKDIR /root/

# Copy our API server
COPY --from=builder /app/api-server ./vpc-api-server
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]