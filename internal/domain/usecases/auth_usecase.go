package usecases

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/anhsbolic/go-secure-auth/internal/domain/helpers"
	"github.com/anhsbolic/go-secure-auth/internal/domain/repositories"
	"github.com/anhsbolic/go-secure-auth/internal/dto"
	"github.com/anhsbolic/go-secure-auth/pkg/dbErrors"
	"github.com/anhsbolic/go-secure-auth/pkg/dbHelpers"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"time"
)

type AuthUseCase interface {
	Register(ctx context.Context, body dto.RegisterRequest) (dto.RegisterResponse, error)
	VerifyEmail(ctx context.Context, email string, token string) error
	ForgotPassword(ctx context.Context, body dto.ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, body dto.ResetPasswordRequest) error
	Login(ctx context.Context, body dto.LoginRequest) error
	VerifyLogin(ctx context.Context, body dto.VerifyLoginRequest) (dto.VerifyLoginResponse, error)
}

type serviceUserUseCase struct {
	DB                        *sqlx.DB
	Validate                  *validator.Validate
	AuthHelper                helpers.AuthHelper
	ActivityAttemptRepository repositories.ActivityAttemptRepository
	ActivityLogRepository     repositories.ActivityLogRepository
	OtpRepository             repositories.OtpRepository
	TokenRepository           repositories.TokenRepository
	UserRepository            repositories.UserRepository
	UserSessionRepository     repositories.UserSessionRepository
}

func (u serviceUserUseCase) Register(ctx context.Context, body dto.RegisterRequest) (dto.RegisterResponse, error) {
	// init empty result
	var result dto.RegisterResponse

	// validate request
	if err := u.Validate.Struct(body); err != nil {
		return result, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// validate password
	if err := u.AuthHelper.ValidatePassword(body.Password); err != nil {
		return result, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// hash username
	hashUsername, err := u.AuthHelper.HashText(body.Username)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errHashText, err)
	}

	// check if username already exists
	isUsernameExist, err := u.UserRepository.CheckByUsernameHash(ctx, u.DB, hashUsername)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errCheckUsername, err)
	}
	if isUsernameExist {
		return result, fiber.NewError(fiber.StatusConflict, "user already exists")
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(body.Email)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errHashText, err)
	}

	// check if email already exists
	isEmailExist, err := u.UserRepository.CheckByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errCheckEmail, err)
	}
	if isEmailExist {
		return result, fiber.NewError(fiber.StatusConflict, "email already exists")
	}

	// encrypt username
	encryptedUsername, err := u.AuthHelper.EncryptText(body.Username)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errEncryptText, err)
	}

	// encrypt email
	encryptedEmail, err := u.AuthHelper.EncryptText(body.Email)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errEncryptText, err)
	}

	// bcrypt password
	hashedPassword, err := u.AuthHelper.BcryptPassword(body.Password)
	if err != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errHashPassword, err)
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// save new user
	createdUser, txErr := u.UserRepository.Create(ctx, tx, entities.User{
		Username:     encryptedUsername,
		UsernameHash: hashUsername,
		Email:        encryptedEmail,
		EmailHash:    hashEmail,
		PasswordHash: hashedPassword,
		Role:         entities.UserRoleMember,
		Status:       entities.UserStatusInactive,
		CreatedAt:    sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		if errors.Is(txErr, dbErrors.DBErrConflict) {
			return result, fiber.NewError(fiber.StatusConflict, "user already exists")
		}
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errCreateUser, txErr)
	}

	// create email verification token
	emailVerificationToken := u.AuthHelper.GenerateEmailVerificationToken(createdUser.ID.String())
	_, txErr = u.TokenRepository.Create(ctx, tx, entities.Token{
		UserID:    createdUser.ID,
		TokenHash: emailVerificationToken,
		TokenType: entities.TokenTypeEmailVerification,
		ExpiresAt: u.AuthHelper.GetEmailVerificationTokenExpirationTime(),
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		if errors.Is(txErr, dbErrors.DBErrConflict) {
			return result, fiber.NewError(fiber.StatusConflict, "token already exists")
		}
		return result, fmt.Errorf("[%s|Register] %s: %w", authUN, errCreateToken, txErr)
	}

	// send email verification
	_ = u.AuthHelper.SendVerificationEmail(body.Email, body.Username, emailVerificationToken)

	// return response
	return dto.RegisterResponse{
		ID:           createdUser.ID,
		Username:     body.Username,
		Email:        body.Email,
		Status:       createdUser.Status,
		RegisteredAt: createdUser.CreatedAt.Time,
	}, nil
}

func (u serviceUserUseCase) VerifyEmail(ctx context.Context, email string, token string) error {
	// NOTES : Invalid verification data should return 422 Unprocessable Entity with Generic Message

	// validate email & token value
	if email == "" || token == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(email)
	if err != nil {
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errHashText, err)
	}

	// get user by email
	user, err := u.UserRepository.FindOneByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
		}
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errFindUserByEmail, err)
	}

	// only for inactive user
	if user.Status != entities.UserStatusInactive {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
	}

	// get token by user id and token
	tokenData, err := u.TokenRepository.FindOneByUserToken(ctx, u.DB, user.ID, token)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
		}
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errFindTokenData, err)
	}

	// check if token was used invalid
	if tokenData.UsedAt.Valid || tokenData.RevokedAt.Valid {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
	}

	// check if token is expired
	if tokenData.ExpiresAt.Before(time.Now()) {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidVerificationData)
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// update user status
	txErr = u.UserRepository.UpdateEmailVerified(ctx, tx, entities.UpdateEmailVerifiedUser{
		ID:              user.ID,
		Status:          entities.UserStatusActive,
		EmailVerifiedAt: time.Now(),
		UpdatedAt:       time.Now(),
	})
	if txErr != nil {
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errUpdateUser, txErr)
	}

	// delete token
	txErr = u.TokenRepository.UpdateTokenUsedAt(ctx, tx, entities.TokenUpdateUsedAt{
		ID:     tokenData.ID,
		UsedAt: time.Now(),
	})
	if txErr != nil {
		return fmt.Errorf("[%s|VerifyEmail] %s: %w", authUN, errUpdateTokenData, txErr)
	}

	return nil
}

func (u serviceUserUseCase) ForgotPassword(ctx context.Context, body dto.ForgotPasswordRequest) error {
	// validate request
	if err := u.Validate.Struct(body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(body.Email)
	if err != nil {
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authUN, errHashText, err)
	}

	// get user by email
	user, err := u.UserRepository.FindOneByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		// add delay before return
		time.Sleep(3 * time.Second)

		// if user not found or error, still return success to prevent from enumeration attack
		return nil
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// revoke all password reset token
	txErr = u.TokenRepository.RevokeUserTokens(ctx, tx, user.ID, entities.TokenTypeResetPassword)
	if txErr != nil {
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authUN, errRevokeTokens, txErr)
	}

	// create password reset token
	resetPassToken := u.AuthHelper.GeneratePasswordResetToken(user.ID.String())
	tokenData := entities.Token{
		UserID:    user.ID,
		TokenType: entities.TokenTypeResetPassword,
		TokenHash: resetPassToken,
		ExpiresAt: u.AuthHelper.GetPasswordResetTokenExpirationTime(),
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	}
	_, txErr = u.TokenRepository.Create(ctx, tx, tokenData)
	if txErr != nil {
		if errors.Is(txErr, dbErrors.DBErrConflict) {
			return fiber.NewError(fiber.StatusConflict, "token already exists")
		}
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authUN, errCreateToken, txErr)
	}

	// send password reset email
	decryptedUsername, err := u.AuthHelper.DecryptText(user.Username)
	if err != nil {
		return fmt.Errorf("[%s|ForgotPassword] %s: %w", authUN, errDecryptText, err)
	}
	_ = u.AuthHelper.SendPasswordResetEmail(body.Email, decryptedUsername, resetPassToken)

	return nil
}

func (u serviceUserUseCase) ResetPassword(ctx context.Context, body dto.ResetPasswordRequest) error {
	// NOTES : Invalid reset password data should return 422 Unprocessable Entity with Generic Message

	// validate request
	if err := u.Validate.Struct(body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(body.Email)
	if err != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errHashText, err)
	}

	// get user by email
	user, err := u.UserRepository.FindOneByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		// add delay before return
		time.Sleep(3 * time.Second)

		// if user not found or error, still return success to prevent from enumeration attack
		return nil
	}

	// get token by user id and token
	tokenData, err := u.TokenRepository.FindOneByUserToken(ctx, u.DB, user.ID, body.ResetToken)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			return fiber.NewError(fiber.StatusUnprocessableEntity, invalidResetPasswordData)
		}
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errFindTokenData, err)
	}

	// check if token was used invalid
	if tokenData.UsedAt.Valid || tokenData.RevokedAt.Valid {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidResetPasswordData)
	}

	// check if token is expired
	if tokenData.ExpiresAt.Before(time.Now()) {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidResetPasswordData)
	}

	// validate password
	err = u.AuthHelper.ValidatePassword(body.NewPassword)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, invalidResetPasswordData)
	}

	// bcrypt password
	hashedNewPassword, err := u.AuthHelper.BcryptPassword(body.NewPassword)
	if err != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errHashPassword, err)
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// update user password
	txErr = u.UserRepository.UpdatePassword(ctx, tx, entities.UpdatePasswordUser{
		ID:           user.ID,
		PasswordHash: hashedNewPassword,
		UpdatedAt:    time.Now(),
	})
	if txErr != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errUpdateUser, txErr)
	}

	// used reset token
	txErr = u.TokenRepository.UpdateTokenUsedAt(ctx, tx, entities.TokenUpdateUsedAt{
		ID:     tokenData.ID,
		UsedAt: time.Now(),
	})
	if txErr != nil {
		return fmt.Errorf("[%s|ResetPassword] %s: %w", authUN, errUpdateTokenData, txErr)
	}

	return nil
}

func (u serviceUserUseCase) Login(ctx context.Context, body dto.LoginRequest) error {
	// validate request
	if err := u.Validate.Struct(body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(body.Email)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errHashText, err)
	}

	// get user by email
	user, err := u.UserRepository.FindOneByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			return fiber.NewError(fiber.StatusUnauthorized, invalidEmailPassword)
		}
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errFindUserByEmail, err)
	}

	// check if user status is blocked
	if user.Status == entities.UserStatusBlocked {
		return fiber.NewError(fiber.StatusForbidden, userBlocked)
	}

	// check login attempt : if user login attempt > 5, block user from login
	maxAttempt := 5
	timeFrame := 15 * time.Minute
	isLoginExceed, err := u.ActivityAttemptRepository.IsExceedMaxAttempt(ctx, u.DB,
		user.ID, entities.ActivityAttemptLogin, maxAttempt, timeFrame)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errExceedMaxLoginAttempts, err)
	}
	if isLoginExceed {
		return fiber.NewError(fiber.StatusTooManyRequests, maxLoginAttemptsExceeded)
	}

	// get user agent & ip address
	userAgent := ctx.Value("user-agent").(string)
	ipAddress := ctx.Value("ip-address").(string)

	// encrypt user agent
	encryptedUserAgent, err := u.AuthHelper.EncryptText(userAgent)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errEncryptText, err)
	}

	// hash user agent
	hashUserAgent, err := u.AuthHelper.HashText(userAgent)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errHashText, err)
	}

	// encrypt ip address
	encryptedIPAddress, err := u.AuthHelper.EncryptText(ipAddress)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errEncryptText, err)
	}

	// hash ip address
	hashIPAddress, err := u.AuthHelper.HashText(ipAddress)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errHashText, err)
	}

	// save login activity
	err = u.ActivityLogRepository.Create(ctx, u.DB, entities.ActivityLog{
		UserID:        user.ID,
		UserAgent:     encryptedUserAgent,
		UserAgentHash: hashUserAgent,
		IPAddress:     encryptedIPAddress,
		IPAddressHash: hashIPAddress,
		Activity:      entities.ActivityLogLogin,
		ActivityTime:  sql.NullTime{Time: time.Now(), Valid: true},
		Description:   sql.NullString{String: "User try to login", Valid: true},
		CreatedAt:     sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errCreateActivityLog, err)
	}

	// check if user can request OTP
	isCanRequestOTP, err := u.OtpRepository.IsUserCanRequestOtp(ctx, u.DB, user.ID, entities.OtpTypeLogin)
	if err != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errIsUserCanRequestOtp, err)
	}
	if !isCanRequestOTP {
		// save failed login attempt
		err = u.ActivityAttemptRepository.Create(ctx, u.DB, entities.ActivityAttempt{
			UserID:      user.ID,
			Activity:    entities.ActivityAttemptLogin,
			AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
			Success:     false,
			Description: sql.NullString{String: maxRequestOtpExceeded, Valid: true},
			CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("[%s|Login] %s: %w", authUN, errCreateActivityAttempt, err)
		}

		// return
		return fiber.NewError(fiber.StatusTooManyRequests, maxRequestOtpExceeded)
	}

	// check password
	isPasswordValid := u.AuthHelper.ComparePassword(user.PasswordHash, body.Password)
	if !isPasswordValid {
		// save failed login attempt
		err = u.ActivityAttemptRepository.Create(ctx, u.DB, entities.ActivityAttempt{
			UserID:      user.ID,
			Activity:    entities.ActivityAttemptLogin,
			AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
			Success:     false,
			Description: sql.NullString{String: invalidPassword, Valid: true},
			CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("[%s|Login] %s: %w", authUN, errCreateActivityAttempt, err)
		}

		// return
		return fiber.NewError(fiber.StatusUnauthorized, "invalid email or password")
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// generate then save OTP
	createdOtp, txErr := u.OtpRepository.Create(ctx, tx, entities.Otp{
		UserID:    user.ID,
		OtpCode:   u.AuthHelper.GenerateLoginOTP(),
		OtpType:   entities.OtpTypeLogin,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errCreateOtp, txErr)
	}

	// send OTP to user email
	decryptedUserEmail, txErr := u.AuthHelper.DecryptText(user.Email)
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errDecryptText, txErr)
	}
	decryptedUsername, txErr := u.AuthHelper.DecryptText(user.Username)
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errDecryptText, txErr)
	}
	txErr = u.AuthHelper.SendLoginOTPEmail(decryptedUserEmail, decryptedUsername, createdOtp.OtpCode)
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errSendEmail, txErr)
	}

	// save success login attempt
	txErr = u.ActivityAttemptRepository.CreateTx(ctx, tx, entities.ActivityAttempt{
		UserID:      user.ID,
		Activity:    entities.ActivityAttemptLogin,
		AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
		Success:     true,
		Description: sql.NullString{String: loginSuccess, Valid: true},
		CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errCreateActivityAttempt, txErr)
	}

	// resolve last login attempts
	txErr = u.ActivityAttemptRepository.ResolveLastAttemptsTx(ctx, tx, user.ID, entities.ActivityAttemptLogin)
	if txErr != nil {
		return fmt.Errorf("[%s|Login] %s: %w", authUN, errResolveLastLoginAttempts, txErr)
	}

	// return
	return nil
}

func (u serviceUserUseCase) VerifyLogin(ctx context.Context, body dto.VerifyLoginRequest) (dto.VerifyLoginResponse, error) {
	// init empty result
	var result dto.VerifyLoginResponse

	// validate request
	if err := u.Validate.Struct(body); err != nil {
		return result, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// hash email
	hashEmail, err := u.AuthHelper.HashText(body.Email)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errHashText, err)
	}

	// get user by email
	user, err := u.UserRepository.FindOneByEmailHash(ctx, u.DB, hashEmail)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			return result, fiber.NewError(fiber.StatusUnauthorized, invalidEmailPassword)
		}
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errFindUserByEmail, err)
	}

	// check if user status is blocked
	if user.Status == entities.UserStatusBlocked {
		return result, fiber.NewError(fiber.StatusForbidden, userBlocked)
	}

	// check login attempt : if user verify login attempt > 5, block user from verify login
	maxAttempt := 5
	timeFrame := 15 * time.Minute
	isLoginExceed, err := u.ActivityAttemptRepository.IsExceedMaxAttempt(ctx, u.DB,
		user.ID, entities.ActivityAttemptVerifyLogin, maxAttempt, timeFrame)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errExceedMaxLoginAttempts, err)
	}
	if isLoginExceed {
		return result, fiber.NewError(fiber.StatusTooManyRequests, maxLoginAttemptsExceeded)
	}

	// get user agent & ip address
	userAgent := ctx.Value("user-agent").(string)
	ipAddress := ctx.Value("ip-address").(string)

	// encrypt user agent
	encryptedUserAgent, err := u.AuthHelper.EncryptText(userAgent)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errEncryptText, err)
	}

	// hash user agent
	hashUserAgent, err := u.AuthHelper.HashText(userAgent)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errHashText, err)
	}

	// encrypt ip address
	encryptedIPAddress, err := u.AuthHelper.EncryptText(ipAddress)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errEncryptText, err)
	}

	// hash ip address
	hashIPAddress, err := u.AuthHelper.HashText(ipAddress)
	if err != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errHashText, err)
	}

	// check password
	isPasswordValid := u.AuthHelper.ComparePassword(user.PasswordHash, body.Password)
	if !isPasswordValid {
		// save failed login attempt
		err = u.ActivityAttemptRepository.Create(ctx, u.DB, entities.ActivityAttempt{
			UserID:      user.ID,
			Activity:    entities.ActivityAttemptVerifyLogin,
			AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
			Success:     false,
			Description: sql.NullString{String: invalidPassword, Valid: true},
			CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errCreateActivityAttempt, err)
		}

		// return
		return result, fiber.NewError(fiber.StatusUnauthorized, invalidEmailPassword)
	}

	// check OTP
	isOtpValid := false
	isOtpFound := true
	userOtp, err := u.OtpRepository.FindOneUserOTP(ctx, u.DB, user.ID, body.Otp)
	if err != nil {
		if errors.Is(err, dbErrors.DBErrNotFound) {
			isOtpFound = false
		} else {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errFindOtp, err)
		}
	}
	if isOtpFound && userOtp.ExpiresAt.After(time.Now()) && userOtp.UsedAt.Valid == false {
		isOtpValid = true
	}
	if !isOtpValid {
		// save failed login attempt
		err = u.ActivityAttemptRepository.Create(ctx, u.DB, entities.ActivityAttempt{
			UserID:      user.ID,
			Activity:    entities.ActivityAttemptVerifyLogin,
			AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
			Success:     false,
			Description: sql.NullString{String: invalidOTP, Valid: true},
			CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errCreateActivityAttempt, err)
		}

		// return
		return result, fiber.NewError(fiber.StatusUnauthorized, invalidOTP)
	}

	// find existing user session
	userSession, err := u.UserSessionRepository.FindOneByMetadata(ctx, u.DB, entities.UserSessionMetadata{
		UserID:        user.ID,
		UserAgentHash: hashUserAgent,
		IPAddressHash: hashIPAddress,
	})
	if err != nil {
		if !errors.Is(err, dbErrors.DBErrNotFound) {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errFindUserSession, err)
		}
	}

	// Init DB Transaction
	tx, txErr := u.DB.BeginTxx(ctx, nil)
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errBeginTx, txErr)
	}
	defer dbHelpers.DbCommitOrRollback(tx, &txErr)

	// if user session already exists, update the session
	isNewSession := false
	if userSession.ID != uuid.Nil {
		userSession.AccessUUID = uuid.New()
		userSession.RefreshUUID = uuid.New()
		userSession.ExpiresAt = u.AuthHelper.GetSessionExpirationTime()
		userSession.UpdatedAt = sql.NullTime{Time: time.Now(), Valid: true}
		txErr = u.UserSessionRepository.RefreshSession(ctx, tx, userSession)
		if txErr != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errRefreshUserSession, txErr)
		}
	} else {
		// if user session not exists, create new session
		userSession, txErr = u.UserSessionRepository.Create(ctx, tx, entities.UserSession{
			SessionID:     uuid.New(),
			UserID:        user.ID,
			Alias:         uuid.New(),
			AccessUUID:    uuid.New(),
			RefreshUUID:   uuid.New(),
			UserAgent:     encryptedUserAgent,
			UserAgentHash: hashUserAgent,
			IPAddress:     encryptedIPAddress,
			IPAddressHash: hashIPAddress,
			ExpiresAt:     u.AuthHelper.GetSessionExpirationTime(),
			CreatedAt:     sql.NullTime{Time: time.Now(), Valid: true},
		})
		if txErr != nil {
			if errors.Is(txErr, dbErrors.DBErrConflict) {
				return result, fiber.NewError(fiber.StatusConflict, "session already exists")
			}
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errCreateUserSession, txErr)
		}
		isNewSession = true
	}

	// generate access token
	userSessionJWT, txErr := u.AuthHelper.GenerateUserSessionJWT(userSession)
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errGenerateJWT, err)
	}

	// update opt used
	txErr = u.OtpRepository.UpdateOtpUsedAt(ctx, tx, entities.OtpUpdateUsedAt{
		ID:     userOtp.ID,
		UsedAt: time.Now(),
	})
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errUpdateOtpUsed, txErr)
	}

	// save success login attempt
	txErr = u.ActivityAttemptRepository.CreateTx(ctx, tx, entities.ActivityAttempt{
		UserID:      user.ID,
		Activity:    entities.ActivityAttemptVerifyLogin,
		AttemptTime: sql.NullTime{Time: time.Now(), Valid: true},
		Success:     true,
		Description: sql.NullString{String: loginSuccess, Valid: true},
		CreatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errCreateActivityAttempt, txErr)
	}

	// resolve last login attempts
	txErr = u.ActivityAttemptRepository.ResolveLastAttemptsTx(ctx, tx, user.ID, entities.ActivityAttemptVerifyLogin)
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errResolveLastLoginAttempts, txErr)
	}

	// save login activity
	actMsg := fmt.Sprintf("User logged in with OTP: %s", userOtp.OtpCode)
	txErr = u.ActivityLogRepository.CreateTx(ctx, tx, entities.ActivityLog{
		UserID:        user.ID,
		UserAgent:     encryptedUserAgent,
		UserAgentHash: hashUserAgent,
		IPAddress:     encryptedIPAddress,
		IPAddressHash: hashIPAddress,
		Activity:      entities.ActivityLogLoggedIn,
		ActivityTime:  sql.NullTime{Time: time.Now(), Valid: true},
		Description:   sql.NullString{String: actMsg, Valid: true},
		CreatedAt:     sql.NullTime{Time: time.Now(), Valid: true},
	})
	if txErr != nil {
		return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errCreateActivityLog, err)
	}

	// send email if new session
	if isNewSession {
		decryptedUserEmail, txErr := u.AuthHelper.DecryptText(user.Email)
		if txErr != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errDecryptText, txErr)
		}
		decryptedUsername, txErr := u.AuthHelper.DecryptText(user.Username)
		if txErr != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errDecryptText, txErr)
		}

		txErr = u.AuthHelper.SendLoginNewMetadataEmail(decryptedUserEmail, decryptedUsername, userAgent, ipAddress)
		if txErr != nil {
			return result, fmt.Errorf("[%s|VerifyLogin] %s: %w", authUN, errSendEmail, txErr)
		}
	}

	// return
	result.AccessToken = userSessionJWT.AccessToken
	result.RefreshToken = userSessionJWT.RefreshToken
	return result, nil
}

func NewAuthUseCase(
	dB *sqlx.DB,
	validate *validator.Validate,
	authHelper helpers.AuthHelper,
	activityAttemptRepository repositories.ActivityAttemptRepository,
	activityLogRepository repositories.ActivityLogRepository,
	otpRepository repositories.OtpRepository,
	tokenRepository repositories.TokenRepository,
	userRepository repositories.UserRepository,
	userSessionRepository repositories.UserSessionRepository,
) AuthUseCase {
	return &serviceUserUseCase{
		DB:                        dB,
		Validate:                  validate,
		AuthHelper:                authHelper,
		ActivityAttemptRepository: activityAttemptRepository,
		ActivityLogRepository:     activityLogRepository,
		OtpRepository:             otpRepository,
		TokenRepository:           tokenRepository,
		UserRepository:            userRepository,
		UserSessionRepository:     userSessionRepository,
	}
}
