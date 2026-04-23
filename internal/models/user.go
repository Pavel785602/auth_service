package models

import (
	"time"

	// Используем стандартный пакет sql для Null-типов
	"database/sql"

	"github.com/google/uuid"
)

// User - главная модель для пользователя в БД (таблица personal_data)
type User struct {
	ID           uuid.UUID      `json:"id" db:"user_id"`
	DisplayName  sql.NullString `json:"display_name" db:"display_name"` // Добавили имя
	Email        sql.NullString `json:"email" db:"email"`
	Username     sql.NullString `json:"username" db:"username"`
	PasswordHash sql.NullString `json:"-" db:"password_hash"`
	PhotoURL     sql.NullString `json:"photo_url" db:"photo_url"` // Наш новый герой
	IsVerified   bool           `json:"is_verified" db:"is_verified"`
	CreatedAt    time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at" db:"updated_at"`
}

// ExternalLogin - модель для внешних идентификаторов (таблица external_logins)
type ExternalLogin struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	Provider   string    `json:"provider" db:"provider"`
	ExternalID string    `json:"external_id" db:"external_id"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// UserInfo - данные, полученные от провайдеров (например, Google)
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// LoginRequest - вход или регистрация (стандартный вход)
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TelegramAuthData struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
	PhotoURL  string `json:"photo_url"`
	AuthDate  int64  `json:"auth_date"` // Unix timestamp
	Hash      string `json:"hash"`      // Хеш для верификации
}

type AuthData struct {
	Token       string
	DisplayName string
	Username    string
	PhotoURL    string
}

// Обнови AuthResponse, чтобы он мог отправить JSON в Android
type AuthResponse struct {
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	InternalToken string `json:"internal_token,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
	Username      string `json:"username,omitempty"`
	PhotoURL      string `json:"photo_url,omitempty"`
}
