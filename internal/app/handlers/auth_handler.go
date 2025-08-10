package handlers

import (
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/usecases"
	"github.com/anhsbolic/go-secure-auth/internal/dto"
	"github.com/gofiber/fiber/v2"
)

type AuthHandler interface {
	Register(ctx *fiber.Ctx) error
	VerifyEmail(ctx *fiber.Ctx) error
	ForgotPassword(ctx *fiber.Ctx) error
	ResetPassword(ctx *fiber.Ctx) error
	Login(ctx *fiber.Ctx) error
	VerifyLogin(ctx *fiber.Ctx) error
	RefreshAccessToken(ctx *fiber.Ctx) error
	GetUserDetails(ctx *fiber.Ctx) error
	ChangePassword(ctx *fiber.Ctx) error
	Logout(ctx *fiber.Ctx) error
	LogoutAll(ctx *fiber.Ctx) error
}

type serviceUserHandler struct {
	AuthUseCase usecases.AuthUseCase
}

func (h serviceUserHandler) Register(ctx *fiber.Ctx) error {
	reqBody := new(dto.RegisterRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|Register] %s: %w", authHN, errFailedParseRequest, err)
	}

	result, err := h.AuthUseCase.Register(ctx.UserContext(), *reqBody)
	if err != nil {
		return err
	}

	return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"message": "User has been registered",
		"data":    result,
	})
}

func (h serviceUserHandler) VerifyEmail(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	token := ctx.Query("token")

	if err := h.AuthUseCase.VerifyEmail(ctx.UserContext(), email, token); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Email has been verified",
	})
}

func (h serviceUserHandler) ForgotPassword(ctx *fiber.Ctx) error {
	reqBody := new(dto.ForgotPasswordRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authHN, errFailedParseRequest, err)
	}

	if err := h.AuthUseCase.ForgotPassword(ctx.UserContext(), *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Reset password link has been sent to your email",
	})
}

func (h serviceUserHandler) ResetPassword(ctx *fiber.Ctx) error {
	reqBody := new(dto.ResetPasswordRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authHN, errFailedParseRequest, err)
	}

	if err := h.AuthUseCase.ResetPassword(ctx.UserContext(), *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Password has been reset",
	})
}

func (h serviceUserHandler) Login(ctx *fiber.Ctx) error {
	reqBody := new(dto.LoginRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authHN, errFailedParseRequest, err)
	}

	fingerprint := dto.FingerPrint{
		UserAgent: ctx.Locals("userAgent").(string),
		IpAddress: ctx.Locals("ipAddress").(string),
	}

	if err := h.AuthUseCase.Login(ctx.UserContext(), fingerprint, *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Login success, please verify your login",
	})
}

func (h serviceUserHandler) VerifyLogin(ctx *fiber.Ctx) error {
	reqBody := new(dto.VerifyLoginRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|VerifyLogin] %s: %w", authHN, errFailedParseRequest, err)
	}

	fingerprint := dto.FingerPrint{
		UserAgent: ctx.Locals("userAgent").(string),
		IpAddress: ctx.Locals("ipAddress").(string),
	}

	result, err := h.AuthUseCase.VerifyLogin(ctx.UserContext(), fingerprint, *reqBody)
	if err != nil {
		return err
	}

	// use it for web apps
	//ctx.Response().Header.Set("Set-Cookie",
	//	fmt.Sprintf("refresh_token=%s; HttpOnly; Path=/; SameSite=Lax", result.RefreshToken),
	//)
	//return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
	//	"success": true,
	//	"message": "Login Verified",
	//	"data":   fiber.Map{
	//		"access_token":  result.AccessToken,
	//	},
	//})

	// user it for mobile apps
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Login Verified",
		"data":    result,
	})
}

func (h serviceUserHandler) RefreshAccessToken(ctx *fiber.Ctx) error {
	userID := ctx.Locals("userId").(string)
	sessionID := ctx.Locals("sessionId").(string)

	result, err := h.AuthUseCase.RefreshAccessToken(ctx.UserContext(), userID, sessionID)
	if err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Access token has been refreshed",
		"data":    result,
	})
}

func (h serviceUserHandler) GetUserDetails(ctx *fiber.Ctx) error {
	userID := ctx.Locals("userId").(string)

	result, err := h.AuthUseCase.GetUserDetail(ctx.UserContext(), userID)
	if err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "User details",
		"data":    result,
	})
}

func (h serviceUserHandler) ChangePassword(ctx *fiber.Ctx) error {
	reqBody := new(dto.ChangePasswordRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|VerifyLogin] %s: %w", authHN, errFailedParseRequest, err)
	}

	userID := ctx.Locals("userId").(string)
	fingerprint := dto.FingerPrint{
		UserAgent: ctx.Locals("userAgent").(string),
		IpAddress: ctx.Locals("ipAddress").(string),
	}

	if err := h.AuthUseCase.ChangePassword(ctx.UserContext(), userID, fingerprint, *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Password has been changed",
	})
}

func (h serviceUserHandler) Logout(ctx *fiber.Ctx) error {
	reqBody := new(dto.LogoutRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|VerifyLogin] %s: %w", authHN, errFailedParseRequest, err)
	}

	fingerprint := dto.FingerPrint{
		UserAgent: ctx.Locals("userAgent").(string),
		IpAddress: ctx.Locals("ipAddress").(string),
	}

	userID := ctx.Locals("userId").(string)
	sessionID := ctx.Locals("sessionId").(string)

	if err := h.AuthUseCase.Logout(ctx.UserContext(), userID, sessionID, fingerprint, *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Logout success",
	})
}

func (h serviceUserHandler) LogoutAll(ctx *fiber.Ctx) error {
	reqBody := new(dto.LogoutRequest)
	if err := ctx.BodyParser(reqBody); err != nil {
		return fmt.Errorf("[%s|VerifyLogin] %s: %w", authHN, errFailedParseRequest, err)
	}

	fingerprint := dto.FingerPrint{
		UserAgent: ctx.Locals("userAgent").(string),
		IpAddress: ctx.Locals("ipAddress").(string),
	}

	userID := ctx.Locals("userId").(string)
	sessionID := ctx.Locals("sessionId").(string)

	if err := h.AuthUseCase.LogoutAll(ctx.UserContext(), userID, sessionID, fingerprint, *reqBody); err != nil {
		return err
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Logout All success",
	})
}

func NewAuthHandler(serviceUserUseCase usecases.AuthUseCase) AuthHandler {
	return &serviceUserHandler{
		AuthUseCase: serviceUserUseCase,
	}
}
