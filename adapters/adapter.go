package adapters

import (
	"context"
	"encoding/gob"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func init() {
	gob.Register(&GothAccount{})
	gob.Register(&GothUser{})
	gob.Register(&GothSession{})
	gob.Register(&GothVerificationToken{})
}

// AccountType represents the type of an account.
type AccountType string

// ErrUnimplemented is returned when a method is not implemented.
var ErrUnimplemented = errors.New("not implemented")

const (
	// AccountTypeOAuth2 represents an OAuth2 account type.
	AccountTypeOAuth2 AccountType = "oauth2"
	// AccountTypeOIDC represents an OIDC account type.
	AccountTypeOIDC AccountType = "oidc"
	// AccountTypeSAML represents a SAML account type.
	AccountTypeSAML AccountType = "saml"
	// AccountTypeEmail represents an email account type.
	AccountTypeEmail AccountType = "email"
	// AccountTypeWebAuthn represents a WebAuthn account type.
	AccountTypeWebAuthn AccountType = "webauthn"
)

// GothAccount represents an account in a third-party identity provider.
type GothAccount struct {
	ID                uuid.UUID   `json:"id" gorm:"primaryKey;type:uuid;column:id;default:gen_random_uuid();"`
	Type              AccountType `json:"type" validate:"required"`
	Provider          string      `json:"provider" validate:"required"`
	ProviderAccountID *string     `json:"provider_account_id"`
	RefreshToken      *string     `json:"refresh_token"`
	AccessToken       *string     `json:"access_token"`
	ExpiresAt         *time.Time  `json:"expires_at"`
	TokenType         *string     `json:"token_type"`
	Scope             *string     `json:"scope"`
	IDToken           *string     `json:"id_token"`
	SessionState      string      `json:"session_state"`
	UserID            *uuid.UUID  `json:"user_id"`
	User              GothUser    `json:"user" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothUser is a user of the application.
type GothUser struct {
	ID            uuid.UUID     `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	Name          string        `json:"name" validate:"required,max=255"`
	Email         string        `json:"email" gorm:"uniqueIndex" validate:"required,email"`
	EmailVerified *bool         `json:"email_verified"`
	Image         *string       `json:"image" validate:"url"`
	Accounts      []GothAccount `json:"accounts" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Sessions      []GothSession `json:"sessions" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothSession is a session for a user.
type GothSession struct {
	ID           uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionToken string    `json:"session_token"`
	UserID       uuid.UUID `json:"user_id"`
	User         GothUser  `json:"user"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// IsValid returns true if the session is valid.
func (s *GothSession) IsValid() bool {
	return s.ExpiresAt.After(time.Now())
}

// GothVerificationToken is a verification token for a user
type GothVerificationToken struct {
	Token      string    `json:"token" gorm:"primaryKey"`
	Identifier string    `json:"identifier"`
	ExpiresAt  time.Time `json:"expires_at"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// Adapter is an interface that defines the methods for interacting with the underlying data storage.
type Adapter interface {
	// CreateUser creates a new user.
	CreateUser(ctx context.Context, user GothUser) (GothUser, error)
	// GetUser retrieves a user by ID.
	GetUser(ctx context.Context, id uuid.UUID) (GothUser, error)
	// GetUserByEmail retrieves a user by email.
	GetUserByEmail(ctx context.Context, email string) (GothUser, error)
	// UpdateUser updates a user.
	UpdateUser(ctx context.Context, user GothUser) (GothUser, error)
	// DeleteUser deletes a user by ID.
	DeleteUser(ctx context.Context, id uuid.UUID) error
	// LinkAccount links an account to a user.
	LinkAccount(ctx context.Context, accountID, userID uuid.UUID) error
	// UnlinkAccount unlinks an account from a user.
	UnlinkAccount(ctx context.Context, accountID, userID uuid.UUID) error
	// CreateSession creates a new session.
	CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (GothSession, error)
	// GetSession retrieves a session by session token.
	GetSession(ctx context.Context, sessionToken string) (GothSession, error)
	// UpdateSession updates a session.
	UpdateSession(ctx context.Context, session GothSession) (GothSession, error)
	// RefreshSession refreshes a session.
	RefreshSession(ctx context.Context, session GothSession) (GothSession, error)
	// DeleteSession deletes a session by session token.
	DeleteSession(ctx context.Context, sessionToken string) error
	// CreateVerificationToken creates a new verification token.
	CreateVerificationToken(ctx context.Context, verficationToken GothVerificationToken) (GothVerificationToken, error)
	// UseVerficationToken uses a verification token.
	UseVerficationToken(ctx context.Context, identifier string, token string) (GothVerificationToken, error)
}

var _ Adapter = (*UnimplementedAdapter)(nil)

// UnimplementedAdapter is an adapter that does not implement any of the methods.
type UnimplementedAdapter struct{}

// CreateUser creates a new user.
func (a *UnimplementedAdapter) CreateUser(_ context.Context, user GothUser) (GothUser, error) {
	return GothUser{}, ErrUnimplemented
}

// GetUser retrieves a user by ID.
func (a *UnimplementedAdapter) GetUser(_ context.Context, id uuid.UUID) (GothUser, error) {
	return GothUser{}, ErrUnimplemented
}

// GetUserByEmail retrieves a user by email.
func (a *UnimplementedAdapter) GetUserByEmail(_ context.Context, email string) (GothUser, error) {
	return GothUser{}, ErrUnimplemented
}

// GetUserByAccount retrieves a user by account.
func (a *UnimplementedAdapter) GetUserByAccount(_ context.Context, provider string, providerAccountID string) (GothUser, error) {
	return GothUser{}, ErrUnimplemented
}

// UpdateUser updates a user.
func (a *UnimplementedAdapter) UpdateUser(_ context.Context, user GothUser) (GothUser, error) {
	return GothUser{}, ErrUnimplemented
}

// DeleteUser deletes a user by ID.
func (a *UnimplementedAdapter) DeleteUser(_ context.Context, id uuid.UUID) error {
	return ErrUnimplemented
}

// LinkAccount links an account to a user.
func (a *UnimplementedAdapter) LinkAccount(_ context.Context, accountID, userID uuid.UUID) error {
	return ErrUnimplemented
}

// UnlinkAccount unlinks an account from a user.
func (a *UnimplementedAdapter) UnlinkAccount(_ context.Context, accountID, userID uuid.UUID) error {
	return ErrUnimplemented
}

// CreateSession creates a new session.
func (a *UnimplementedAdapter) CreateSession(_ context.Context, userID uuid.UUID, expires time.Time) (GothSession, error) {
	return GothSession{}, ErrUnimplemented
}

// GetSession retrieves a session by session token.
func (a *UnimplementedAdapter) GetSession(_ context.Context, sessionToken string) (GothSession, error) {
	return GothSession{}, ErrUnimplemented
}

// UpdateSession updates a session.
func (a *UnimplementedAdapter) UpdateSession(_ context.Context, session GothSession) (GothSession, error) {
	return GothSession{}, ErrUnimplemented
}

// RefreshSession refreshes a session.
func (a *UnimplementedAdapter) RefreshSession(_ context.Context, session GothSession) (GothSession, error) {
	return GothSession{}, ErrUnimplemented
}

// DeleteSession deletes a session by session token.
func (a *UnimplementedAdapter) DeleteSession(_ context.Context, sessionToken string) error {
	return ErrUnimplemented
}

// CreateVerificationToken creates a new verification token.
func (a *UnimplementedAdapter) CreateVerificationToken(_ context.Context, erficationToken GothVerificationToken) (GothVerificationToken, error) {
	return GothVerificationToken{}, ErrUnimplemented
}

// UseVerficationToken uses a verification token.
func (a *UnimplementedAdapter) UseVerficationToken(_ context.Context, identifier string, token string) (GothVerificationToken, error) {
	return GothVerificationToken{}, ErrUnimplemented
}

// StringPtr returns a pointer to the string value passed in.
func StringPtr(s string) *string {
	return &s
}

// TimePtr returns a pointer to the time value passed in.
func TimePtr(t time.Time) *time.Time {
	return &t
}
