package middleware

import "github.com/gofiber/fiber/v2"

func LimitRequestSizeMiddleware(ctx *fiber.Ctx) error {
	if len(ctx.Body()) > 2*1024*1024 {
		return ctx.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
			"error": "Request body too large",
		})
	}
	return ctx.Next()
}
