package credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/zeiss/fiber-goth/adapters"
	"github.com/zeiss/fiber-goth/providers"
	"github.com/zeiss/pkg/dbx"
	"golang.org/x/crypto/bcrypt"

	"gorm.io/gorm"
)

type User struct {
	// ID is the unique identifier of the user.
	ID uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	// Name is the name of the user.
	Name string `gorm:"size:255"`
	// Email is the email of the user.
	Email string `gorm:"type:varchar(100);unique_index"`
	// HashedPassword is the hashed password of the user.
	HashedPassword []byte
	// Active is true if the user is active.
	Active bool
	// CreatedAt is the creation time of the user.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the user.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the user.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// SetNewPassword set a new hashsed password to user.
func (user *User) SetNewPassword(password string) error {
	hash, err := dbx.HashPassword([]byte(password))
	if err != nil {
		return err
	}

	user.HashedPassword = hash

	return nil
}

type credentialsProvider struct {
	db *gorm.DB

	providers.UnimplementedProvider
}

type authIntent struct {
	authURL string
}

// GetAuthURL returns the URL for the authentication end-point.
func (a *authIntent) GetAuthURL() (string, error) {
	if a.authURL == "" {
		return "", providers.ErrNoAuthURL
	}

	return a.authURL, nil
}

// Opt is a function that configures the credentials provider.
type Opt func(*credentialsProvider)

// New creates a new GitHub provider.
func New(db *gorm.DB, opts ...Opt) *credentialsProvider {
	p := &credentialsProvider{
		db: db,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// HashPassword returns the bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedPassword), nil
}

// BeginAuth starts the authentication process.
func (e *credentialsProvider) BeginAuth(ctx context.Context, adapter adapters.Adapter, state string, params providers.AuthParams) (providers.AuthIntent, error) {
	return &authIntent{
		authURL: "",
	}, nil
}
