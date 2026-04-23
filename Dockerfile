FROM golang:1.24-alpine AS builder
RUN apk --no-cache git
WORKDIR /app
COPY . .
RUN go mod tidy
