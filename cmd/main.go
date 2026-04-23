package main

import (
	"log"
	"math/rand"
	"net/http"
	"time"

	"auth_service/internal/cache"
	"auth_service/internal/config"
	"auth_service/internal/db"
	"auth_service/internal/handlers"
	"auth_service/internal/repository"
	"auth_service/internal/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
)

func main() {
	// 1. КОНФИГУРАЦИЯ
	appCfg := config.LoadConfig()

	// 2. ИНИЦИАЛИЗАЦИЯ DB
	dbPool, err := db.NewDBPool(appCfg.DBConfig)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize database pool: %v", err)
	}
	defer dbPool.Close()

	// 3. ИНИЦИАЛИЗАЦИЯ REDIS КЛИЕНТА
	redisClient := cache.NewRedisClient(
		appCfg.RedisConfig.RedisMasterName,
		appCfg.RedisConfig.RedisSentinels,
		appCfg.RedisConfig.Password,
		appCfg.RedisConfig.DB,
	)

	// Проверяем подключение к Redis
	if err := redisClient.Ping(); err != nil {
		log.Fatalf("FATAL: Failed to connect to Redis: %v", err)
	}
	log.Println("Redis client initialized successfully.")

	// 4. ИНИЦИАЛИЗАЦИЯ GOOGLE OAUTH CONFIG
	googleOauthConfig := &oauth2.Config{
		ClientID:     appCfg.OAuthConfig.ClientID,
		ClientSecret: appCfg.OAuthConfig.ClientSecret,
		Scopes:       []string{"email", "profile"},
		RedirectURL:  appCfg.OAuthConfig.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}

	// Устанавливаем seed (старый стиль для совместимости, если нужно)
	rand.Seed(time.Now().UnixNano())

	// 5. ВНЕДРЕНИЕ ЗАВИСИМОСТЕЙ (СБОРКА СЛОЕВ)
	userRepo := repository.NewPostgresUserRepository(dbPool)

	// Инициализируем AuthService
	authService := service.NewAuthService(
		userRepo,
		redisClient,
		googleOauthConfig,
		appCfg.OAuthConfig.JWTSecret,
		appCfg.OAuthConfig.TelegramBotToken,
	)

	// Передаем токен бота напрямую в хэндлер, если нужно выводить его имя в HTML
	authHandler := handlers.NewAuthHandler(googleOauthConfig, authService)

	// 6. НАСТРОЙКА РОУТИНГА С ИСПОЛЬЗОВАНИЕМ CHI
	router := chi.NewRouter()

	// Добавление Middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Health Check & Metrics
	router.Get("/health", authHandler.HealthCheck)
	router.Handle("/metrics", promhttp.Handler())

	// ГРУППА МАРШРУТОВ /auth
	router.Route("/auth", func(r chi.Router) {
		// --- 1. Email/Password ---
		r.Post("/register", authHandler.HandleRegister)
		r.Post("/login", authHandler.HandleLogin)
		r.Post("/verify", authHandler.HandleVerifyCode)
		r.Post("/resend", authHandler.HandleResendCode)

		// --- 2. Google OAuth ---
		r.Get("/google/login", authHandler.HandleGoogleLogin)
		r.Get("/google/callback", authHandler.HandleGoogleCallback)

		// --- 3. Telegram (WebView & API) ---

		// Отдает HTML страницу с виджетом для Android WebView
		r.Get("/telegram/login-page", authHandler.HandleTelegramLoginPage)

		// Пустой эндпоинт, который перехватывает Android при редиректе
		r.Get("/telegram/callback", authHandler.HandleTelegramCallback)

		// Финальный прием данных из Android и выдача JWT
		r.Post("/telegram/login", authHandler.HandleTelegramLogin)
	})

	// 7. ЗАПУСК СЕРВЕРА
	port := appCfg.ServicePort
	if port == "" {
		port = "8080"
	}
	log.Printf("🚀 Auth Service is starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
