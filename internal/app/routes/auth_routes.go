package routes

import (
	"github.com/anhsbolic/go-secure-auth/internal/app/handlers"
	"github.com/anhsbolic/go-secure-auth/internal/domain/helpers"
	"github.com/anhsbolic/go-secure-auth/internal/domain/repositories"
	"github.com/anhsbolic/go-secure-auth/internal/domain/usecases"
	"github.com/anhsbolic/go-secure-auth/internal/infrastructure/api/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

func InitAuthRoutes(f fiber.Router, db *sqlx.DB, validate *validator.Validate) {
	// Init Repositories
	activityAttemptRepository := repositories.NewActivityAttemptRepository()
	activityLogRepository := repositories.NewActivityLogRepository()
	otpRepository := repositories.NewOtpRepository()
	tokenRepository := repositories.NewTokenRepository()
	userRepository := repositories.NewUserRepository()
	userSessionRepository := repositories.NewUserSessionRepository()

	// Init helper, usecase, handler, and group route
	authHelper := helpers.NewAuthHelper()
	authUseCase := usecases.NewAuthUseCase(db, validate, authHelper, activityAttemptRepository, activityLogRepository,
		otpRepository, tokenRepository, userRepository, userSessionRepository)
	authHandler := handlers.NewAuthHandler(authUseCase)
	authRoutes := f.Group("/auth")

	// Set Middleware IF NEEDED
	authRoutes.Use(middleware.FingerprintMiddleware)

	// Init Routes
	authRoutes.Post("/register", authHandler.Register)
	authRoutes.Get("/verify-email", authHandler.VerifyEmail)
	authRoutes.Post("/forgot-password", authHandler.ForgotPassword)
	authRoutes.Post("/reset-password", authHandler.ResetPassword)
	authRoutes.Post("/login", authHandler.Login)
	authRoutes.Post("/verify-login", authHandler.VerifyLogin)
}
