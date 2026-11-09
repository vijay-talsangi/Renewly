// Package services contains all working of every services
package services

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgx/v5/pgconn"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrMissingJWTSecret   = errors.New("jwt secret is not configured")
	ErrEmailExists        = errors.New("email is already registered")
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
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrEmailExists
		}
		return err
	}

	return nil
}

// GetByID returns the user for an authenticated browser session. Callers must
// obtain the ID from a validated session cookie, never from request input.
func (us *UserService) GetByID(ctx context.Context, id int64) (db.User, error) {
	return us.q.GetUserByID(ctx, id)
}

func (us *UserService) Login(
	ctx context.Context,
	input LoginInput,
) (string, error) {
	userID, err := us.AuthenticateCredentials(
		ctx,
		input.Email,
		input.Password,
	)
	if err != nil {
		return "", err
	}

	return signJWT(userID)
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

func (us *UserService) AuthenticateCredentials(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	user, err := us.q.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	); err != nil {
		return 0, ErrInvalidCredentials
	}

	return user.ID, nil
}
