package adapters

import (
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

// Account represents an account.
type Account struct {
	ID                uuid.UUID              `json:"id"`
	Type              AccountType            `json:"type"`
	Provider          string                 `json:"provider"`
	ProviderAccountID string                 `json:"provider_account_id"`
	RefreshToken      string                 `json:"refresh_token"`
	AccessToken       string                 `json:"access_token"`
	ExpiresAt         time.Time              `json:"expires_at"`
	TokenType         string                 `json:"token_type"`
	Scope             string                 `json:"scope"`
	IDToken           string                 `json:"id_token"`
	SessionState      string                 `json:"session_state"`
	UserID            uuid.UUID              `json:"user_id"`
	RawData           map[string]interface{} `json:"raw_data"`
}

// User represents a user.
type User struct {
	ID            uuid.UUID              `json:"id"`
	Name          string                 `json:"name"`
	Email         string                 `json:"email"`
	EmailVerified string                 `json:"email_verified"`
	Image         string                 `json:"image"`
	RawData       map[string]interface{} `json:"raw_data"`
}

// Session represents a session.
type Session struct {
	ID           uuid.UUID `json:"id"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionToken string    `json:"session_token"`
	UserID       uuid.UUID `json:"user_id"`
}

// VerificationToken represents a verification token.
type VerificationToken struct {
	Token      string    `json:"token"`
	Identifier string    `json:"identifier"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Adapter is an interface that defines the methods for interacting with the underlying data storage.
type Adapter interface {
	// CreateAccount creates a new account.
	CreateUser(user *User) (*User, error)
	// GetUser retrieves a user by ID.
	GetUser(ID string) (*User, error)
	// GetUserByEmail retrieves a user by email.
	GetUserByEmail(email string) (*User, error)
	// GetUserByAccount retrieves a user by account.
	GetUserByAccount(provider string, providerAccountID string) (*User, error)
	// UpdateUser updates a user.
	UpdateUser(user *User) (*User, error)
	// DeleteUser deletes a user by ID.
	DeleteUser(ID string) error
	// LinkAccount links an account to a user.
	LinkAccount(accountID, userID uuid.UUID) error
	// UnlinkAccount unlinks an account from a user.
	UnlinkAccount(accountID, userID uuid.UUID) error
	// CreateSession creates a new session.
	CreateSession(session *Session) (*Session, error)
	// GetSession retrieves a session by session token.
	GetSession(sessionToken string) (*Session, error)
	// UpdateSession updates a session.
	UpdateSession(session *Session) (*Session, error)
	// DeleteSession deletes a session by session token.
	DeleteSession(sessionToken string) error
	// CreateVerificationToken creates a new verification token.
	CreateVerificationToken(verficationToken *VerificationToken) (*VerificationToken, error)
	// UseVerficationToken uses a verification token.
	UseVerficationToken(identifier string, token string) (*VerificationToken, error)
}

var _ Adapter = (*UnimplementedAdapter)(nil)

// UnimplementedAdapter is an adapter that does not implement any of the methods.
type UnimplementedAdapter struct{}

// CreateUser creates a new user.
func (a *UnimplementedAdapter) CreateUser(user *User) (*User, error) {
	return nil, ErrUnimplemented
}

// GetUser retrieves a user by ID.
func (a *UnimplementedAdapter) GetUser(id string) (*User, error) {
	return nil, ErrUnimplemented
}

// GetUserByEmail retrieves a user by email.
func (a *UnimplementedAdapter) GetUserByEmail(email string) (*User, error) {
	return nil, ErrUnimplemented
}

// GetUserByAccount retrieves a user by account.
func (a *UnimplementedAdapter) GetUserByAccount(provider string, providerAccountID string) (*User, error) {
	return nil, ErrUnimplemented
}

// UpdateUser updates a user.
func (a *UnimplementedAdapter) UpdateUser(user *User) (*User, error) {
	return nil, ErrUnimplemented
}

// DeleteUser deletes a user by ID.
func (a *UnimplementedAdapter) DeleteUser(id string) error {
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
func (a *UnimplementedAdapter) CreateSession(session *Session) (*Session, error) {
	return nil, ErrUnimplemented
}

// GetSession retrieves a session by session token.
func (a *UnimplementedAdapter) GetSession(sessionToken string) (*Session, error) {
	return nil, ErrUnimplemented
}

// UpdateSession updates a session.
func (a *UnimplementedAdapter) UpdateSession(session *Session) (*Session, error) {
	return nil, ErrUnimplemented
}

// DeleteSession deletes a session by session token.
func (a *UnimplementedAdapter) DeleteSession(sessionToken string) error {
	return ErrUnimplemented
}

// CreateVerificationToken creates a new verification token.
func (a *UnimplementedAdapter) CreateVerificationToken(verficationToken *VerificationToken) (*VerificationToken, error) {
	return nil, ErrUnimplemented
}

// UseVerficationToken uses a verification token.
func (a *UnimplementedAdapter) UseVerficationToken(identifier string, token string) (*VerificationToken, error) {
	return nil, ErrUnimplemented
}
