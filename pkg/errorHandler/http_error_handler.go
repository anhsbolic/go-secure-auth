package errorHandler

import (
	"errors"
	"github.com/anhsbolic/go-secure-auth/pkg/logging"
	"github.com/gofiber/fiber/v2"
	"io"
	"net/http"
)

// GetHttpErrorHandler is a function to handle http error
func GetHttpErrorHandler(ctx *fiber.Ctx, err error) error {
	// Status code defaults to 500
	code := fiber.StatusInternalServerError

	// Retrieve the custom status code if it's a *fiber.Error
	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
	}

	// Return if Not Found
	if code == fiber.StatusNotFound {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	// Return if Bad Request
	if code == fiber.StatusBadRequest {
		return ctx.Status(code).JSON(fiber.Map{
			"success":    false,
			"message":    "Bad Request",
			"error_code": "BAD_REQUEST",
			"error":      err.Error(),
		})
	}

	// Return if Unauthorized
	if code == fiber.StatusUnauthorized {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	// Return if Forbidden
	if code == fiber.StatusForbidden {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": "Forbidden",
		})
	}

	// Return if Unprocessable Entity
	if code == fiber.StatusUnprocessableEntity {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	// Return if conflict
	if code == fiber.StatusConflict {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	// Return If Too Many Requests
	if code == fiber.StatusTooManyRequests {
		return ctx.Status(code).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	// Logging Error
	logging.Logger().Error(err)

	// Return Internal Server Error
	return ctx.Status(code).JSON(fiber.Map{
		"success": false,
		"message": "Internal Server Error",
	})
}

// LogExternalApiError is a function to log external api error
func LogExternalApiError(res *http.Response, message string) {
	errBody := "An error occurred while calling external API"
	bodyBytes, err := io.ReadAll(res.Body)
	if err == nil {
		errBody = string(bodyBytes)
	}
	logging.Logger().Errorf(
		"[External Api], %s, statusCode: %d, status: %s, error: %s",
		message,
		res.StatusCode,
		res.Status,
		errBody,
	)
}
