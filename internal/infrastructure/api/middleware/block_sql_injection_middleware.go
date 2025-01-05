package middleware

import (
	"github.com/gofiber/fiber/v2"
	"regexp"
)

func BlockSqlInjectionMiddleware(ctx *fiber.Ctx) error {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(union|select|insert|update|delete|drop|truncate|alter|exec|create|rename)\b`),
		regexp.MustCompile(`--|/\*|\*/|;`),
	}

	hasSuspiciousInput := func(input []byte) bool {
		for _, re := range patterns {
			if re.Match(input) {
				return true
			}
		}
		return false
	}

	var suspicious bool
	ctx.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		if hasSuspiciousInput(value) {
			suspicious = true
		}
	})

	if suspicious {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Suspicious input detected in query parameters",
		})
	}

	if len(ctx.Body()) > 0 && hasSuspiciousInput(ctx.Body()) {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Suspicious input detected in request body",
		})
	}

	return ctx.Next()
}
