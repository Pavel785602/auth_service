package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"time"

	"auth_service/internal/cache"
	"auth_service/internal/models"
	"auth_service/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// IAuthService - контракт сервиса
type IAuthService interface {
	AuthenticateWithGoogle(ctx context.Context, code string) (string, error)
	AuthenticateWithTelegram(ctx context.Context, authData string) (*models.AuthData, error)
	RegisterUser(ctx context.Context, email string, password string) (string, error)
	LoginUser(ctx context.Context, email string, password string) (string, error)
	SendVerificationCode(ctx context.Context, email string) error
	VerifyCode(ctx context.Context, email string, code string) (string, error)
}

type AuthService struct {
	Repo             repository.IUserRepository
	RedisClient      cache.IRedisClient
	OAuthConfig      *oauth2.Config
	JWTSecret        string
	TelegramBotToken string
}

func NewAuthService(repo repository.IUserRepository, redisClient cache.IRedisClient, config *oauth2.Config, jwtSecret string, tgBotToken string) *AuthService {
	return &AuthService{
		Repo:             repo,
		RedisClient:      redisClient,
		OAuthConfig:      config,
		JWTSecret:        jwtSecret,
		TelegramBotToken: tgBotToken,
	}
}

// --- Хелперы ---

func generateOTP() string {
	const otpLength = 6
	const otpChars = "0123456789"
	b := make([]byte, otpLength)
	for i := range b {
		b[i] = otpChars[rand.Intn(len(otpChars))]
	}
	return string(b)
}

func (s *AuthService) generateJWT(userID string) (string, error) {
	expirationTime := time.Now().Add(720 * time.Hour)
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     expirationTime.Unix(),
		"iss":     "auth_service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.JWTSecret))
}

func (s *AuthService) FindUserInfoFromGoogle(ctx context.Context, token *oauth2.Token) (*models.UserInfo, error) {
	const userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	client := s.OAuthConfig.Client(ctx, token)
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var userInfo models.UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func (s *AuthService) checkTelegramHash(data models.TelegramAuthData, botToken string) bool {
	params := map[string]string{
		"id":         fmt.Sprintf("%d", data.ID),
		"auth_date":  fmt.Sprintf("%d", data.AuthDate),
		"first_name": data.FirstName,
		"username":   data.Username,
		"photo_url":  data.PhotoURL,
	}
	var keys []string
	for k, v := range params {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var dataCheckParts []string
	for _, k := range keys {
		dataCheckParts = append(dataCheckParts, fmt.Sprintf("%s=%s", k, params[k]))
	}
	checkString := strings.Join(dataCheckParts, "\n")
	sha := sha256.New()
	sha.Write([]byte(botToken))
	secretKey := sha.Sum(nil)
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(checkString))
	computedHash := hex.EncodeToString(mac.Sum(nil))
	return strings.EqualFold(computedHash, data.Hash)
}

// --- Основные методы ---

func (s *AuthService) AuthenticateWithTelegram(ctx context.Context, authData string) (*models.AuthData, error) {
	var tgData models.TelegramAuthData

	// ЛОГ 1: Что прислал Android
	log.Printf("DEBUG: Raw authData from Android: %s", authData)

	if err := json.Unmarshal([]byte(authData), &tgData); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}

	// ЛОГ 2: Что распарсилось в структуру
	log.Printf("DEBUG: Parsed tgData: ID=%d, Name=%s, PhotoURL=%s", tgData.ID, tgData.FirstName, tgData.PhotoURL)

	if !s.checkTelegramHash(tgData, s.TelegramBotToken) {
		// Если здесь упало — значит либо бот-токен не тот, либо в JSON нет photo_url, а в проверке хеша он есть
		return nil, errors.New("hash verification failed")
	}

	tgIDString := fmt.Sprintf("%d", tgData.ID)
	user, err := s.Repo.FindUserByExternalID("TELEGRAM", tgIDString)

	if err != nil {
		log.Printf("DEBUG: User not found, creating new one for TG ID: %s", tgIDString)

		// Создаем пользователя
		user, err = s.Repo.CreateUser(nil, &tgData.Username, nil, &tgData.FirstName, &tgData.PhotoURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		err = s.Repo.CreateExternalLogin(user.ID, "TELEGRAM", tgIDString)
		if err != nil {
			log.Printf("ERROR: Failed to create external login link: %v", err)
		}
	}

	token, _ := s.generateJWT(user.ID.String())

	return &models.AuthData{
		Token:       token,
		DisplayName: user.DisplayName.String,
		Username:    user.Username.String,
		PhotoURL:    user.PhotoURL.String,
	}, nil
}

func (s *AuthService) AuthenticateWithGoogle(ctx context.Context, code string) (string, error) {
	token, err := s.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		return "", err
	}
	googleUser, err := s.FindUserInfoFromGoogle(ctx, token)
	if err != nil {
		return "", err
	}

	user, err := s.Repo.FindUserByExternalID("GOOGLE", googleUser.ID)
	if err != nil {
		user, _, err = s.Repo.FindUserByEmailWithHash(googleUser.Email)
		if errors.Is(err, repository.ErrUserNotFound) {
			// ИСПРАВЛЕНО: Теперь 5 аргументов (email, username, pwd, name, photo)
			user, err = s.Repo.CreateUser(&googleUser.Email, nil, nil, &googleUser.Name, nil)
		}
		_ = s.Repo.CreateExternalLogin(user.ID, "GOOGLE", googleUser.ID)
	}

	return s.generateJWT(user.ID.String())
}

func (s *AuthService) RegisterUser(ctx context.Context, email string, password string) (string, error) {
	_, _, err := s.Repo.FindUserByEmailWithHash(email)
	if err == nil {
		return "", errors.New("user already exists")
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	pwdStr := string(hash)

	// ИСПРАВЛЕНО: Теперь 5 аргументов
	_, err = s.Repo.CreateUser(&email, nil, &pwdStr, nil, nil)
	if err != nil {
		return "", err
	}

	_ = s.SendVerificationCode(ctx, email)
	return "VERIFICATION_PENDING", nil
}

// Остальные методы (LoginUser, VerifyCode, SendVerificationCode) остаются без изменений сигнатур
func (s *AuthService) LoginUser(ctx context.Context, email string, password string) (string, error) {
	user, hashedPassword, err := s.Repo.FindUserByEmailWithHash(email)
	if err != nil {
		return "", errors.New("invalid credentials")
	}
	if !user.IsVerified {
		return "", errors.New("not verified")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return "", errors.New("invalid credentials")
	}
	return s.generateJWT(user.ID.String())
}

func (s *AuthService) SendVerificationCode(ctx context.Context, email string) error {
	user, _, err := s.Repo.FindUserByEmailWithHash(email)
	if err != nil {
		return err
	}
	if user.IsVerified {
		return nil
	}
	code := generateOTP()
	_ = s.RedisClient.SetCode(ctx, email, code, 10*time.Minute)
	log.Printf("Code for %s: %s", email, code)
	return nil
}

func (s *AuthService) VerifyCode(ctx context.Context, email string, code string) (string, error) {
	expCode, err := s.RedisClient.GetCode(ctx, email)
	if err != nil || expCode != code {
		return "", errors.New("invalid code")
	}
	_ = s.Repo.MarkUserAsVerified(email)
	user, _, _ := s.Repo.FindUserByEmailWithHash(email)
	return s.generateJWT(user.ID.String())
}
