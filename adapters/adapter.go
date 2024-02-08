package adapters

import (
	"context"
	"encoding/gob"
	"errors"
	"time"

	"github.com/google/uuid"
)

func init() {
	gob.Register(&Account{})
	gob.Register(&User{})
	gob.Register(&Session{})
	gob.Register(&VerificationToken{})
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

// Account ...
type Account struct {
	ID                uuid.UUID   `json:"id" gorm:"primaryKey;type:uuid;column:id;default:gen_random_uuid();"`
	Type              AccountType `json:"type"`
	Provider          string      `json:"provider"`
	ProviderAccountID *string     `json:"provider_account_id"`
	RefreshToken      *string     `json:"refresh_token"`
	AccessToken       *string     `json:"access_token"`
	ExpiresAt         *time.Time  `json:"expires_at"`
	TokenType         *string     `json:"token_type"`
	Scope             *string     `json:"scope"`
	IDToken           *string     `json:"id_token"`
	SessionState      string      `json:"session_state"`
	UserID            *uuid.UUID  `json:"user_id"`
	User              User        `json:"user" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
}

// User ...
type User struct {
	ID            uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified *bool     `json:"email_verified"`
	Image         *string   `json:"image"`
	Accounts      []Account `json:"accounts" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Sessions      []Session `json:"sessions" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
}

// Session ...
type Session struct {
	ID           uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionToken string    `json:"session_token"`
	UserID       uuid.UUID `json:"user_id"`
	User         User      `json:"user" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt *time.Time
}

// VerificationToken ...
type VerificationToken struct {
	Token      string    `json:"token" gorm:"primaryKey"`
	Identifier string    `json:"identifier"`
	ExpiresAt  time.Time `json:"expires_at"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
}

// Adapter is an interface that defines the methods for interacting with the underlying data storage.
type Adapter interface {
	// CreateUser creates a new user.
	CreateUser(ctx context.Context, user User) (User, error)
	// GetUser retrieves a user by ID.
	GetUser(id uuid.UUID) (User, error)
	// GetUserByEmail retrieves a user by email.
	GetUserByEmail(email string) (User, error)
	// UpdateUser updates a user.
	UpdateUser(user User) (User, error)
	// DeleteUser deletes a user by ID.
	DeleteUser(id uuid.UUID) error
	// LinkAccount links an account to a user.
	LinkAccount(accountID, userID uuid.UUID) error
	// UnlinkAccount unlinks an account from a user.
	UnlinkAccount(accountID, userID uuid.UUID) error
	// CreateSession creates a new session.
	CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (Session, error)
	// GetSession retrieves a session by session token.
	GetSession(sessionToken string) (Session, error)
	// UpdateSession updates a session.
	UpdateSession(session Session) (Session, error)
	// DeleteSession deletes a session by session token.
	DeleteSession(sessionToken string) error
	// CreateVerificationToken creates a new verification token.
	CreateVerificationToken(verficationToken VerificationToken) (VerificationToken, error)
	// UseVerficationToken uses a verification token.
	UseVerficationToken(identifier string, token string) (VerificationToken, error)
}

var _ Adapter = (*UnimplementedAdapter)(nil)

// UnimplementedAdapter is an adapter that does not implement any of the methods.
type UnimplementedAdapter struct{}

// CreateUser creates a new user.
func (a *UnimplementedAdapter) CreateUser(_ context.Context, user User) (User, error) {
	return User{}, ErrUnimplemented
}

// GetUser retrieves a user by ID.
func (a *UnimplementedAdapter) GetUser(id uuid.UUID) (User, error) {
	return User{}, ErrUnimplemented
}

// GetUserByEmail retrieves a user by email.
func (a *UnimplementedAdapter) GetUserByEmail(email string) (User, error) {
	return User{}, ErrUnimplemented
}

// GetUserByAccount retrieves a user by account.
func (a *UnimplementedAdapter) GetUserByAccount(provider string, providerAccountID string) (User, error) {
	return User{}, ErrUnimplemented
}

// UpdateUser updates a user.
func (a *UnimplementedAdapter) UpdateUser(user User) (User, error) {
	return User{}, ErrUnimplemented
}

// DeleteUser deletes a user by ID.
func (a *UnimplementedAdapter) DeleteUser(id uuid.UUID) error {
	return ErrUnimplemented
}

// LinkAccount links an account to a user.
func (a *UnimplementedAdapter) LinkAccount(accountID, userID uuid.UUID) error {
	return ErrUnimplemented
}

// UnlinkAccount unlinks an account from a user.
func (a *UnimplementedAdapter) UnlinkAccount(accountID, userID uuid.UUID) error {
	return ErrUnimplemented
}

// CreateSession creates a new session.
func (a *UnimplementedAdapter) CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (Session, error) {
	return Session{}, ErrUnimplemented
}

// GetSession retrieves a session by session token.
func (a *UnimplementedAdapter) GetSession(sessionToken string) (Session, error) {
	return Session{}, ErrUnimplemented
}

// UpdateSession updates a session.
func (a *UnimplementedAdapter) UpdateSession(session Session) (Session, error) {
	return Session{}, ErrUnimplemented
}

// DeleteSession deletes a session by session token.
func (a *UnimplementedAdapter) DeleteSession(sessionToken string) error {
	return ErrUnimplemented
}

// CreateVerificationToken creates a new verification token.
func (a *UnimplementedAdapter) CreateVerificationToken(verficationToken VerificationToken) (VerificationToken, error) {
	return VerificationToken{}, ErrUnimplemented
}

// UseVerficationToken uses a verification token.
func (a *UnimplementedAdapter) UseVerficationToken(identifier string, token string) (VerificationToken, error) {
	return VerificationToken{}, ErrUnimplemented
}

// GetAccount retrieve by provider and provider account ID.
func (a *UnimplementedAdapter) GetAccount(provider string, providerAccountID string) (Account, error) {
	return Account{}, ErrUnimplemented
}

// StringPtr returns a pointer to the string value passed in.
func StringPtr(s string) *string {
	return &s
}

// TimePtr returns a pointer to the time value passed in.
func TimePtr(t time.Time) *time.Time {
	return &t
}
