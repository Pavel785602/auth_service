package handlers

import (
	"auth_service/internal/models"
	"auth_service/internal/service"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type AuthHandler struct {
	OAuthConfig *oauth2.Config
	AuthService service.IAuthService
}

func NewAuthHandler(config *oauth2.Config, service service.IAuthService) *AuthHandler {
	return &AuthHandler{
		OAuthConfig: config,
		AuthService: service,
	}
}

// --- Хелперы ---

func (h *AuthHandler) logClientError(r *http.Request, errCode string, message string) {
	logData := map[string]interface{}{
		"level":      "INFO",
		"type":       "CLIENT_ERROR",
		"request_id": r.Header.Get("X-Request-Id"),
		"remote_ip":  r.Header.Get("X-Forwarded-For"),
		"error_code": errCode,
		"message":    message,
		"path":       r.URL.Path,
		"time":       time.Now().Format(time.RFC3339),
	}
	jsonData, _ := json.Marshal(logData)
	log.Println(string(jsonData))
}

func (h *AuthHandler) sendJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// --- Хэндлеры ---

func (h *AuthHandler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// В идеале: генерировать случайный state и сохранять в Cookie/Redis
	url := h.OAuthConfig.AuthCodeURL("random-state-string")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if googleErr := r.FormValue("error"); googleErr != "" {
		h.logClientError(r, "GOOGLE_ACCESS_DENIED", googleErr)
		h.sendJSONResponse(w, http.StatusUnauthorized, models.AuthResponse{Status: "error", Message: "Authentication cancelled"})
		return
	}

	code := r.FormValue("code")
	if code == "" {
		h.logClientError(r, "MISSING_OAUTH_CODE", "No code in callback")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{Status: "error", Message: "Missing code"})
		return
	}

	internalToken, err := h.AuthService.AuthenticateWithGoogle(r.Context(), code)
	if err != nil {
		if strings.Contains(err.Error(), "invalid_grant") {
			h.logClientError(r, "GOOGLE_CODE_EXPIRED", err.Error())
			h.sendJSONResponse(w, http.StatusUnauthorized, models.AuthResponse{Status: "error", Message: "Session expired"})
			return
		}
		log.Printf("[SERVER_ERROR] Google callback failure: %v", err)
		h.sendJSONResponse(w, http.StatusInternalServerError, models.AuthResponse{Status: "error", Message: "Internal server error"})
		return
	}

	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{
		Status:        "success",
		Message:       "Authenticated via Google",
		InternalToken: internalToken,
	})
}

func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logClientError(r, "BAD_REQUEST", "Invalid JSON")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{Status: "error", Message: "Invalid request body"})
		return
	}

	status, err := h.AuthService.RegisterUser(r.Context(), req.Email, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "already in use") {
			h.logClientError(r, "EMAIL_ALREADY_EXISTS", req.Email)
			h.sendJSONResponse(w, http.StatusConflict, models.AuthResponse{Status: "error", Message: "Email already registered"})
			return
		}
		log.Printf("[SERVER_ERROR] Registration failed: %v", err)
		h.sendJSONResponse(w, http.StatusInternalServerError, models.AuthResponse{Status: "error", Message: "Registration failed"})
		return
	}

	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{Status: "success", Message: status})
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logClientError(r, "BAD_REQUEST", "Invalid JSON")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{Status: "error", Message: "Invalid request body"})
		return
	}

	internalToken, err := h.AuthService.LoginUser(r.Context(), req.Email, req.Password)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid credentials") {
			h.logClientError(r, "INVALID_CREDENTIALS", req.Email)
			h.sendJSONResponse(w, http.StatusUnauthorized, models.AuthResponse{Status: "error", Message: "Invalid credentials"})
			return
		}
		if strings.Contains(errMsg, "not verified") {
			h.logClientError(r, "USER_NOT_VERIFIED", req.Email)
			h.sendJSONResponse(w, http.StatusForbidden, models.AuthResponse{Status: "error", Message: "Email not verified"})
			return
		}
		log.Printf("[SERVER_ERROR] Login failure for %s: %v", req.Email, err)
		h.sendJSONResponse(w, http.StatusInternalServerError, models.AuthResponse{Status: "error", Message: "Login failed"})
		return
	}

	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{Status: "success", InternalToken: internalToken})
}

func (h *AuthHandler) HandleVerifyCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logClientError(r, "BAD_REQUEST", "Invalid JSON")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{Status: "error", Message: "Invalid request body"})
		return
	}

	internalToken, err := h.AuthService.VerifyCode(r.Context(), req.Email, req.Code)
	if err != nil {
		h.logClientError(r, "INVALID_VERIFY_CODE", req.Email)
		h.sendJSONResponse(w, http.StatusUnauthorized, models.AuthResponse{Status: "error", Message: "Invalid or expired code"})
		return
	}

	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{Status: "success", InternalToken: internalToken})
}

func (h *AuthHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("Write error: %v", err)
	}
}

// HandleResendCode: Принимает Email и повторно отправляет код верификации.
func (h *AuthHandler) HandleResendCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logClientError(r, "BAD_REQUEST", "Invalid JSON body for resend")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{
			Status:  "error",
			Message: "Invalid request body",
		})
		return
	}

	// 1. Вызов сервиса для повторной отправки кода
	if err := h.AuthService.SendVerificationCode(r.Context(), req.Email); err != nil {
		// Ошибка сервиса (например, SMTP лежит) - обычный лог
		log.Printf("[SERVER_ERROR] Resend failed for %s: %v", req.Email, err)
		h.sendJSONResponse(w, http.StatusInternalServerError, models.AuthResponse{
			Status:  "error",
			Message: "Failed to resend verification code",
		})
		return
	}

	// 2. Успех
	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{
		Status:  "success",
		Message: "Verification code successfully resent.",
	})
}

// 1. GET /auth/telegram/login-page
// Этот метод просто отдает HTML с виджетом Telegram
func (h *AuthHandler) HandleTelegramLoginPage(w http.ResponseWriter, r *http.Request) {
	// В идеале: вынести имя бота в конфиг
	botUsername := "qq_dev_bot"
	callbackURL := "http://api.proxy.of.by/auth/telegram/callback"

	html := `
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #242f3e; }
        </style>
    </head>
    <body>
        <script async src="https://telegram.org/js/telegram-widget.js?22" 
            data-telegram-login="` + botUsername + `" 
            data-size="large" 
            data-auth-url="` + callbackURL + `">
        </script>
    </body>
    </html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	if _, err := w.Write([]byte(html)); err != nil {
		log.Printf("Write error: %v", err)
	}
}

// 2. GET /auth/telegram/callback
// Сюда Telegram редиректит пользователя.
// Android-приложение "увидит" этот URL и заберет параметры.
func (h *AuthHandler) HandleTelegramCallback(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Авторизация получена, возвращайтесь в приложение..."))
}

// 3. POST /auth/telegram/login (уже есть у тебя, немного уточним)
func (h *AuthHandler) HandleTelegramLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		h.logClientError(r, "EMPTY_BODY", "No telegram data")
		h.sendJSONResponse(w, http.StatusBadRequest, models.AuthResponse{Status: "error", Message: "Request body is empty"})
		return
	}

	// authData теперь имеет тип *models.AuthData, в котором есть все нужные поля
	authData, err := h.AuthService.AuthenticateWithTelegram(r.Context(), string(body))
	if err != nil {
		h.logClientError(r, "TELEGRAM_AUTH_INVALID", err.Error())
		h.sendJSONResponse(w, http.StatusUnauthorized, models.AuthResponse{
			Status:  "error",
			Message: "Telegram auth failed: " + err.Error(),
		})
		return
	}

	// Теперь ошибки undefined исчезнут, так как поля существуют в модели AuthData
	h.sendJSONResponse(w, http.StatusOK, models.AuthResponse{
		Status:        "success",
		InternalToken: authData.Token,
		DisplayName:   authData.DisplayName,
		Username:      authData.Username,
		PhotoURL:      authData.PhotoURL,
	})
}
