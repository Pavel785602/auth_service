FROM golang:1.26-alpine AS builder

# Устанавливаем зависимости для сборки (если нужны)
RUN apk add --no-cache git

WORKDIR /app

# Сначала копируем зависимости, чтобы Docker закешировал этот слой
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходники
COPY . .

# Собираем статический бинарник (CGO_ENABLED=0 важен для запуска в пустом alpine)
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/service ./cmd/main.go

# Stage 2: Runtime
FROM alpine:3.21.0
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Копируем бинарник из билдера
COPY --from=builder /app/service .

# Если сервису нужны конфиги в файлах — раскомментируй:
# COPY --from=builder /app/config ./config 

EXPOSE 8080

CMD ["./service"]