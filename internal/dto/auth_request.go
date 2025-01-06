package dto

type RegisterRequest struct {
	Username string `json:"username" validate:"required,min=4,max=255"`
	Password string `json:"password" validate:"required,min=8,max=32"`
	Email    string `json:"email" validate:"required,email,min=5,max=255"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,min=5,max=255"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email" validate:"required,email,min=5,max=255"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=32"`
	ResetToken  string `json:"reset_token" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email,min=5,max=255"`
	Password string `json:"password" validate:"required,min=8,max=32"`
}

type VerifyLoginRequest struct {
	Email    string `json:"email" validate:"required,email,min=5,max=255"`
	Password string `json:"password" validate:"required,min=8,max=32"`
	Otp      string `json:"otp" validate:"required,min=6,max=6"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required,min=8,max=32"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=32"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}
