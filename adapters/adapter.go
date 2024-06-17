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
	// ID is the unique identifier of the account.
	ID uuid.UUID `json:"id" gorm:"primaryKey;type:uuid;column:id;default:gen_random_uuid();"`
	// Type is the type of the account.
	Type AccountType `json:"type" validate:"required"`
	// Provider is the provider of the account.
	Provider string `json:"provider" validate:"required"`
	// ProviderAccountID is the account ID in the provider.
	ProviderAccountID *string `json:"provider_account_id"`
	// RefreshToken is the refresh token of the account.
	RefreshToken *string `json:"refresh_token"`
	// AccessToken is the access token of the account.
	AccessToken *string `json:"access_token"`
	// ExpiresAt is the expiry time of the account.
	ExpiresAt *time.Time `json:"expires_at"`
	// TokenType is the token type of the account.
	TokenType *string `json:"token_type"`
	// Scope is the scope of the account.
	Scope *string `json:"scope"`
	// IDToken is the ID token of the account.
	IDToken *string `json:"id_token"`
	// SessionState is the session state of the account.
	SessionState string `json:"session_state"`
	// UserID is the user ID of the account.
	UserID *uuid.UUID `json:"user_id"`
	//  User is the user of the account.
	User GothUser `json:"user" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	// CreatedAt is the creation time of the account.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the account.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the account.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothUser is a user of the application.
type GothUser struct {
	// ID is the unique identifier of the user.
	ID uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	// Name is the name of the user.
	Name string `json:"name" validate:"required,max=255"`
	// Email is the email of the user.
	Email string `json:"email" gorm:"uniqueIndex" validate:"required,email"`
	// EmailVerified is true if the email is verified.
	EmailVerified *bool `json:"email_verified"`
	// Image is the image URL of the user.
	Image *string `json:"image" validate:"url"`
	// Password is the password of the user.
	Accounts []GothAccount `json:"accounts" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	// Sessions are the sessions of the user.
	Sessions []GothSession `json:"sessions" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	// Teams are the teams the user is a member of.
	Teams *[]GothTeam `json:"teams" gorm:"many2many:team_users"`
	// CreatedAt is the creation time of the user.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the user.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the user.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothSession is a session for a user.
type GothSession struct {
	// ID is the unique identifier of the session.
	ID uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	// SessionToken is the token of the session.
	SessionToken string `json:"session_token"`
	// UserID is the user ID of the session.
	UserID uuid.UUID `json:"user_id"`
	// User is the user of the session.
	User GothUser `json:"user"`
	// ExpiresAt is the expiry time of the session.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is the creation time of the session.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the session.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the session.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// IsValid returns true if the session is valid.
func (s *GothSession) IsValid() bool {
	return s.ExpiresAt.After(time.Now())
}

// GothVerificationToken is a verification token for a user
type GothVerificationToken struct {
	// Token is the unique identifier of the token.
	Token string `json:"token" gorm:"primaryKey"`
	// Identifier is the identifier of the token.
	Identifier string `json:"identifier"`
	// ExpiresAt is the expiry time of the token.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is the creation time of the token.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the token.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the token.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothTeam is a team in the application.
type GothTeam struct {
	// ID is the unique identifier of the team.
	ID uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	// Name is the name of the team.
	Name string `json:"name" validate:"required,max=255"`
	// Slug is the slug of the team.
	Slug string `json:"slug" validate:"required,min=3,max=255"`
	// Description is the description of the team.
	Description string `json:"description" validate:"max=255"`
	// Users are the users in the team.
	Users []GothUser `json:"users" gorm:"many2many:team_users"`
	// Roles are the roles in the team.
	Roles []GothRole `json:"roles" gorm:"foreignKey:TeamID;constraint:OnDelete:CASCADE"`
	// CreatedAt is the creation time of the team.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the team.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the team.
	DeletedAt gorm.DeletedAt `json:"deleted_at"`
}

// GothRole is a role in the application.
type GothRole struct {
	// ID is the unique identifier of the role.
	ID uuid.UUID `json:"id" gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	// Name is the name of the role.
	Name string `json:"name" validate:"required,min=3,max=255"`
	// Description is the description of the role.
	Description string `json:"description" validate:"max=255"`
	// TeamID is the team ID of the role.
	TeamID uuid.UUID `json:"team_id"`
	// Team is the team of the role.
	Team GothTeam `json:"team"`
	// CreatedAt is the creation time of the role.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the update time of the role.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is the deletion time of the role.
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
