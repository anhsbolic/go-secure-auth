package middleware

import (
	"database/sql"
	"errors"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/anhsbolic/go-secure-auth/pkg/crypt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
)

func RefreshTokenMiddleware(db *sqlx.DB) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// init unauthorized return
		unauthorized := ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Unauthorized",
		})

		// Get Authorization Header
		tokenString := ctx.Get("Authorization")
		if tokenString == "" || len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			return unauthorized
		}

		// Get Config
		cfg := config.GetConfig()
		JWTSecretKey := []byte(cfg.JWTSecretKey)
		appName := cfg.AppName

		// Parse Token with validation (exp, iat, nbf)
		token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid signing method")
			}
			return JWTSecretKey, nil
		})

		if err != nil || !token.Valid {
			return unauthorized
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return unauthorized
		}

		// Validate claims : iss
		if claims["iss"] != appName {
			return unauthorized
		}

		// check session with alias, sessionId, and refreshUUID
		alias, ok := claims["sub"].(string)
		if !ok {
			return unauthorized
		}
		sessionID, ok := claims["sid"].(string)
		if !ok {
			return unauthorized
		}
		refreshUUID, ok := claims["jti"].(string)
		if !ok {
			return unauthorized
		}

		// get ip dan user agent
		ipAddress := ctx.IP()
		userAgent := ctx.Get(fiber.HeaderUserAgent, "Unknown")

		// hash ip dan user agent
		ipAddressHash := crypt.ComputeSHA256(ipAddress)
		userAgentHash := crypt.ComputeSHA256(userAgent)

		// get session from database
		var userSession entities.UserSession
		query := `SELECT * FROM user_sessions WHERE alias = $1 AND session_id = $2 AND refresh_uuid = $3  
                              AND ip_address_hash = $4 AND user_agent_hash = $5 AND expires_at > NOW()  
                              AND revoked_at IS NULL AND deleted_at IS NULL`
		err = db.GetContext(ctx.Context(), &userSession, query, alias, sessionID, refreshUUID, ipAddressHash, userAgentHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return unauthorized
			}
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Internal Server Error",
			})
		}

		// Set some data to context
		ctx.Locals("userId", userSession.UserID.String())
		ctx.Locals("sessionId", userSession.SessionID.String())

		// Next middleware or handler
		return ctx.Next()
	}
}
