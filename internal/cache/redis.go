package cache

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// IRedisClient - контракт для кеша OTP
type IRedisClient interface {
	GetCode(ctx context.Context, email string) (string, error)
	SetCode(ctx context.Context, email string, code string, expiration time.Duration) error
	Ping() error
}

type RedisClient struct {
	RDB *redis.Client
}

// NewRedisClient: Создает и тестирует подключение к Redis
func NewRedisClient(masterName string, sentinelAddrs []string, password string, db int) IRedisClient {
	rdb := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    masterName,
		SentinelAddrs: sentinelAddrs,
		Password:      password,
		// Обязательно добавляем пароль для самих Sentinel
		SentinelPassword: password,
		DB:               db,
	})

	// Проверка подключения
	// Используем контекст с таймаутом, чтобы Ping не висел вечно при проблемах в сети K8s
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		// Выводим в лог список сентинелей и имя мастера для удобства отладки
		log.Fatalf("FATAL: Cannot connect to Redis via Sentinels %v (Master: %s): %v",
			sentinelAddrs, masterName, err)
	}

	log.Printf("Connected to Redis Sentinel. Master: %s, Sentinels: %v", masterName, sentinelAddrs)

	return &RedisClient{RDB: rdb}
}

// SetCode: Устанавливает код с TTL
func (r *RedisClient) SetCode(ctx context.Context, email string, code string, expiration time.Duration) error {
	// Ключ: email:verification
	key := fmt.Sprintf("%s:verification", email)
	return r.RDB.Set(ctx, key, code, expiration).Err()
}

// GetCode: Извлекает код
func (r *RedisClient) GetCode(ctx context.Context, email string) (string, error) {
	key := fmt.Sprintf("%s:verification", email)
	val, err := r.RDB.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("verification code not found or expired")
	}
	if err != nil {
		return "", fmt.Errorf("redis read error: %w", err)
	}
	return val, nil
}

func (r *RedisClient) Ping() error {
	// Мы уже проверили подключение в NewRedisClient,
	// но для соответствия интерфейсу метод должен быть.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return r.RDB.Ping(ctx).Err()
}
