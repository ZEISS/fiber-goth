package gorm_adapter

import (
	"context"
	"time"

	goth "github.com/zeiss/fiber-goth"
	"github.com/zeiss/fiber-goth/adapters"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations is a helper function to run the migrations for the database.
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&adapters.GothAccount{},
		&adapters.GothUser{},
		&adapters.GothSession{},
		&adapters.GothVerificationToken{},
	)
	if err != nil {
		return err
	}

	return nil
}

var _ adapters.Adapter = (*gormAdapter)(nil)

type gormAdapter struct {
	db *gorm.DB

	adapters.UnimplementedAdapter
}

// New ...
func New(db *gorm.DB) (*gormAdapter, error) {
	err := RunMigrations(db)
	if err != nil {
		return nil, err
	}

	return &gormAdapter{db, adapters.UnimplementedAdapter{}}, nil
}

// CreateUser is a helper function to create a new user.
func (a *gormAdapter) CreateUser(ctx context.Context, user adapters.GothUser) (adapters.GothUser, error) {
	err := a.db.WithContext(ctx).FirstOrCreate(&user).Error
	if err != nil {
		return adapters.GothUser{}, goth.ErrMissingUser
	}

	return user, nil
}

// GetSession is a helper function to retrieve a session by session token.
func (a *gormAdapter) GetSession(ctx context.Context, sessionToken string) (adapters.GothSession, error) {
	var session adapters.GothSession
	err := a.db.WithContext(ctx).Preload("User").Where("session_token = ?", sessionToken).First(&session).Error
	if err != nil {
		return adapters.GothSession{}, goth.ErrMissingSession
	}

	return session, nil
}

// GetUser is a helper function to retrieve a user by ID.
func (a *gormAdapter) GetUser(ctx context.Context, id uuid.UUID) (adapters.GothUser, error) {
	var user adapters.GothUser
	err := a.db.WithContext(ctx).Preload("Accounts").Where("id = ?", id).First(&user).Error
	if err != nil {
		return adapters.GothUser{}, goth.ErrMissingUser
	}

	return user, nil
}

// CreateSession is a helper function to create a new session.
func (a *gormAdapter) CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (adapters.GothSession, error) {
	session := adapters.GothSession{UserID: userID, SessionToken: uuid.NewString(), ExpiresAt: expires}
	err := a.db.WithContext(ctx).Create(&session).Error
	if err != nil {
		return adapters.GothSession{}, goth.ErrBadSession
	}

	return session, nil
}

// DeleteSession is a helper function to delete a session by session token.
func (a *gormAdapter) DeleteSession(ctx context.Context, sessionToken string) error {
	err := a.db.WithContext(ctx).Where("session_token = ?", sessionToken).Delete(&adapters.GothSession{}).Error
	if err != nil {
		return goth.ErrBadRequest
	}

	return nil
}

// RefreshSession is a helper function to refresh a session.
func (a *gormAdapter) RefreshSession(ctx context.Context, session adapters.GothSession) (adapters.GothSession, error) {
	err := a.db.WithContext(ctx).Model(&adapters.GothSession{}).Where("session_token = ?", session.SessionToken).Updates(&session).Error
	if err != nil {
		return adapters.GothSession{}, goth.ErrBadSession
	}

	return session, nil
}

// DeleteUser is a helper function to delete a user by ID.
func (a *gormAdapter) DeleteUser(ctx context.Context, id uuid.UUID) error {
	err := a.db.WithContext(ctx).Where("id = ?", id).Delete(&adapters.GothUser{}).Error
	if err != nil {
		return goth.ErrBadRequest
	}

	return nil
}

// LinkAccount is a helper function to link an account to a user.
func (a *gormAdapter) LinkAccount(ctx context.Context, accountID, userID uuid.UUID) error {
	err := a.db.WithContext(ctx).Model(&adapters.GothAccount{}).Where("id = ?", accountID).Update("user_id", userID).Error
	if err != nil {
		return goth.ErrBadRequest
	}

	return nil
}
