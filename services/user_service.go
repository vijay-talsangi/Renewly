package services

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrMissingJWTSecret   = errors.New("jwt secret is not configured")
)

type RegisterInput struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type UserService struct {
	q *db.Queries
}

func NewUserService(q *db.Queries) *UserService {
	return &UserService{q: q}
}

func (us *UserService) Register(ctx context.Context, input RegisterInput) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = us.q.CreateUser(ctx, db.CreateUserParams{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: string(hashedPassword),
	})

	return err
}

func (us *UserService) Login(ctx context.Context, input LoginInput) (string, error) {
	user, err := us.q.GetUserByEmail(ctx, input.Email)
	if err != nil {
		return "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return "", ErrInvalidCredentials
	}

	token, err := signJWT(user.ID)
	if err != nil {
		return "", err
	}

	return token, nil
}

func signJWT(userID int64) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", ErrMissingJWTSecret
	}

	now := time.Now()

	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
