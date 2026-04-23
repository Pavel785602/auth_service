package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// DBConfig хранит параметры подключения к Postgres
type DBConfig struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
}

// RedisConfig хранит параметры подключения к Redis через Sentinel
type RedisConfig struct {
	RedisMasterName string
	RedisSentinels  []string
	Password        string
	DB              int
}

// OAuthConfig хранит настройки аутентификации
type OAuthConfig struct {
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	JWTSecret        string
	TelegramBotToken string
}

// AppConfig объединяет все конфигурации приложения
type AppConfig struct {
	ServicePort string
	OAuthConfig
	DBConfig
	RedisConfig
}

// LoadConfig загружает переменные из .env и возвращает объединенную структуру AppConfig
func LoadConfig() AppConfig {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, relying on environment variables.")
	}

	// Чтение порта Redis и конвертация в int
	redisDBStr := getEnvWithDefault("REDIS_DB", "0")
	redisDB, _ := strconv.Atoi(redisDBStr)

	appCfg := AppConfig{
		ServicePort: getEnvWithDefault("SERVICE_PORT", "8080"),

		OAuthConfig: OAuthConfig{
			ClientID:         os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret:     os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:      os.Getenv("GOOGLE_REDIRECT_URL"),
			JWTSecret:        os.Getenv("JWT_SECRET"),
			TelegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		},
		DBConfig: DBConfig{
			DBHost:     os.Getenv("DB_HOST"),
			DBPort:     os.Getenv("DB_PORT"),
			DBUser:     os.Getenv("DB_USER"),
			DBPassword: os.Getenv("DB_PASSWORD"),
			DBName:     os.Getenv("DB_NAME"),
			DBSSLMode:  os.Getenv("DB_SSLMODE"),
		},
		RedisConfig: RedisConfig{
			// Вместо Addr используем параметры Sentinel
			RedisMasterName: getEnvWithDefault("REDIS_MASTER_NAME", "mymaster"),
			RedisSentinels:  splitEnv("REDIS_SENTINELS", "control-plane-redis-service.vpn-system.svc.cluster.local:26379"),
			Password:        os.Getenv("REDIS_PASSWORD"),
			DB:              redisDB,
		},
	}

	// Валидация
	if appCfg.OAuthConfig.TelegramBotToken == "" {
		log.Fatal("FATAL: TELEGRAM_BOT_TOKEN is missing!")
	}

	if appCfg.OAuthConfig.ClientID == "" || appCfg.OAuthConfig.JWTSecret == "" || appCfg.DBConfig.DBUser == "" {
		log.Fatal("FATAL: Critical environment variables are missing (ClientID, JWT_SECRET, or DB_USER).")
	}

	// Проверка Sentinel (минимум один адрес должен быть)
	if len(appCfg.RedisConfig.RedisSentinels) == 0 {
		log.Fatal("FATAL: REDIS_SENTINELS configuration is missing.")
	}

	return appCfg
}

// Вспомогательная функция для значений по умолчанию
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Вспомогательная функция для разделения строки адресов (например, "addr1:26379,addr2:26379")
func splitEnv(key, defaultValue string) []string {
	value := os.Getenv(key)
	if value == "" {
		value = defaultValue
	}
	parts := strings.Split(value, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
