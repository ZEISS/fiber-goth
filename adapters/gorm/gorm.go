package gorm_adapter

import (
	"context"
	"time"

	"github.com/zeiss/fiber-goth/adapters"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations is a helper function to run the migrations for the database.
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&adapters.Account{},
		&adapters.User{},
		&adapters.Session{},
		&adapters.VerificationToken{},
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

// CreateUser ...
func (a *gormAdapter) CreateUser(ctx context.Context, user adapters.User) (adapters.User, error) {
	err := a.db.WithContext(ctx).FirstOrCreate(&user).Error
	if err != nil {
		return adapters.User{}, err
	}

	return user, nil
}

// GetSession ...
func (a *gormAdapter) GetSession(ctx context.Context, sessionToken string) (adapters.Session, error) {
	var session adapters.Session
	err := a.db.WithContext(ctx).Where("session_token = ?", sessionToken).First(&session).Error
	if err != nil {
		return adapters.Session{}, err
	}

	return session, nil
}

// GetUser ...
func (a *gormAdapter) GetUser(ctx context.Context, id uuid.UUID) (adapters.User, error) {
	var user adapters.User
	err := a.db.WithContext(ctx).Preload("Accounts").Where("id = ?", id).First(&user).Error
	if err != nil {
		return adapters.User{}, err
	}

	return user, nil
}

// CreateSession ...
func (a *gormAdapter) CreateSession(ctx context.Context, userID uuid.UUID, expires time.Time) (adapters.Session, error) {
	session := adapters.Session{UserID: userID, SessionToken: uuid.NewString(), ExpiresAt: expires}
	err := a.db.WithContext(ctx).Create(&session).Error
	if err != nil {
		return adapters.Session{}, err
	}

	return session, nil
}

// DeleteUser ...
func (a *gormAdapter) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return a.db.WithContext(ctx).Where("id = ?", id).Delete(&adapters.User{}).Error
}

// LinkAccount ...
func (a *gormAdapter) LinkAccount(ctx context.Context, accountID, userID uuid.UUID) error {
	return a.db.WithContext(ctx).Model(&adapters.Account{}).Where("id = ?", accountID).Update("user_id", userID).Error
}

// DeleteSession ...
func (a *gormAdapter) DeleteSession(ctx context.Context, sessionToken string) error {
	return a.db.WithContext(ctx).Where("session_token = ?", sessionToken).Delete(&adapters.Session{}).Error
}
