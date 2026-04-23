package repository

import (
	"auth_service/internal/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUserNotFound = errors.New("user not found or not registered with password")

// IUserRepository - контракт репозитория
type IUserRepository interface {
	// Используется для входа по Email/Password
	FindUserByEmailWithHash(email string) (*models.User, string, error)

	// !!! НОВЫЙ МЕТОД: Поиск по Внешнему ID (Telegram, Google Sub ID)
	FindUserByExternalID(provider string, externalID string) (*models.User, error)

	// Создание пользователя (только personal_data)
	CreateUser(email, username, passwordHash, displayName, photoUrl *string) (*models.User, error)
	// !!! НОВЫЙ МЕТОД: Создание записи внешнего логина
	CreateExternalLogin(userID uuid.UUID, provider string, externalID string) error

	MarkUserAsVerified(email string) error
	// FindUserByEmail - удален, так как он не универсален для всех логинов
}

// PostgresUserRepository - реализация контракта
type PostgresUserRepository struct {
	Pool *pgxpool.Pool
}

func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{Pool: pool}
}

// --- НОВЫЙ МЕТОД: FindUserByExternalID (Для Telegram и Google) ---
// Ищет пользователя по внешнему ID и провайдеру, используя external_logins
func (r *PostgresUserRepository) FindUserByExternalID(provider string, externalID string) (*models.User, error) {
	user := &models.User{}
	query := `
        SELECT 
            p.user_id, 
            p.email, 
            p.is_verified, 
            p.username, 
            p.password_hash, 
            p.created_at, 
            p.updated_at,
            p.display_name, -- ДОБАВИЛИ
            p.photo_url     -- ДОБАВИЛИ
        FROM external_logins e
        JOIN personal_data p ON e.user_id = p.user_id
        WHERE e.provider = $1 AND e.external_id = $2
    `
	row := r.Pool.QueryRow(context.Background(), query, provider, externalID)

	// Теперь Scan совпадает по количеству полей с SELECT
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.IsVerified,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DisplayName,
		&user.PhotoURL,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("postgres_repo/FindUserByExternalID: user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database query error: %w", err)
	}
	return user, nil
}

// --- НОВЫЙ МЕТОД: CreateExternalLogin (Для связывания аккаунтов) ---
// Связывает внешний ID (Telegram/Google) с созданным user_id (UUID)
func (r *PostgresUserRepository) CreateExternalLogin(userID uuid.UUID, provider string, externalID string) error {
	query := `
        INSERT INTO external_logins (user_id, provider, external_id)
        VALUES ($1, $2, $3)
    `
	_, err := r.Pool.Exec(context.Background(), query, userID, provider, externalID)
	if err != nil {
		return fmt.Errorf("postgres_repo/CreateExternalLogin: failed to create external login for user %s: %w", userID.String(), err)
	}
	return nil
}

// --- FindUserByEmailWithHash (МОДИФИЦИРОВАН) ---
// Ищет пользователя по Email и возвращает хеш (только для Email/Пароль входа)
func (r *PostgresUserRepository) FindUserByEmailWithHash(email string) (*models.User, string, error) {
	user := &models.User{}
	var hashedPassword sql.NullString // Оставляем, так как возвращаем её отдельно

	query := `
        SELECT user_id, email, username, password_hash, is_verified, created_at, updated_at 
        FROM personal_data 
        WHERE email = $1 AND password_hash IS NOT NULL
    `
	row := r.Pool.QueryRow(context.Background(), query, email)

	// !!! ИСПРАВЛЕНИЕ: Сканируем напрямую в поля user.Email и user.Username (тип sql.NullString) !!!
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&hashedPassword,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		// ИСПОЛЬЗУЕМ МАРКЕР, который будет распознан сервисом
		return nil, "", ErrUserNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("postgres_repo/FindUserByEmailWithHash: database query error: %w", err)
	}
	return user, hashedPassword.String, nil
}

// --- MarkUserAsVerified (МОДИФИЦИРОВАН) ---
// Обновляет флаг is_verified. Теперь нужно решить, по какому полю обновлять.
// Оставляем по email, предполагая, что верификация идет после регистрации по email/password.
func (r *PostgresUserRepository) MarkUserAsVerified(email string) error {
	query := `UPDATE personal_data SET is_verified = TRUE WHERE email = $1`
	commandTag, err := r.Pool.Exec(context.Background(), query, email)
	if err != nil {
		return fmt.Errorf("postgres_repo/MarkUserAsVerified: failed to update verification status: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("postgres_repo/MarkUserAsVerified: user not found for email: %s", email)
	}
	return nil
}

// CreateUser создает запись в personal_data.
// Теперь принимает 5 параметров: email, username, passwordHash, displayName, photoUrl.
func (r *PostgresUserRepository) CreateUser(
	email *string,
	username *string,
	passwordHash *string,
	displayName *string,
	photoUrl *string,
) (*models.User, error) {
	user := &models.User{}

	// 1. Предварительная очистка данных
	var cleanEmail, cleanUsername, cleanDisplayName, cleanPhotoUrl *string

	if email != nil && *email != "" {
		trimmed := strings.ToLower(strings.TrimSpace(*email))
		cleanEmail = &trimmed
	}

	if username != nil && *username != "" {
		trimmed := strings.ToLower(strings.TrimSpace(*username))
		trimmed = strings.TrimPrefix(trimmed, "@")
		cleanUsername = &trimmed
	}

	if displayName != nil && *displayName != "" {
		trimmed := strings.TrimSpace(*displayName)
		cleanDisplayName = &trimmed
	}

	if photoUrl != nil && *photoUrl != "" {
		trimmed := strings.TrimSpace(*photoUrl)
		cleanPhotoUrl = &trimmed
	}

	// 2. SQL запрос (убедись, что колонки в базе называются именно так)
	query := `
        INSERT INTO personal_data (email, username, password_hash, display_name, photo_url)
        VALUES ($1, $2, $3, $4, $5) 
        RETURNING user_id, email, username, display_name, photo_url, is_verified, created_at, updated_at
    `

	// 3. Выполнение и Scan в структуру модели
	err := r.Pool.QueryRow(
		context.Background(),
		query,
		cleanEmail,
		cleanUsername,
		passwordHash, // Хеш пароля может быть nil, если это OAuth
		cleanDisplayName,
		cleanPhotoUrl,
	).Scan(
		&user.ID,
		&user.Email,       // Поле в модели должно быть sql.NullString
		&user.Username,    // Поле в модели должно быть sql.NullString
		&user.DisplayName, // Поле в модели должно быть sql.NullString
		&user.PhotoURL,    // Поле в модели должно быть sql.NullString
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	log.Printf("DEBUG Created user photo_url in model: %v (valid=%v)", user.PhotoURL.String, user.PhotoURL.Valid)

	if err != nil {
		log.Printf("DATABASE ERROR [CreateUser]: %v", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}
