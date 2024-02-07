package gorm_adapter

import (
	"time"

	"github.com/zeiss/fiber-goth/adapters"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunMigrations ...
func RunMigrations(db *gorm.DB) error {
	err := db.AutoMigrate(
		&Account{},
		&User{},
		&Session{},
		&VerificationToken{},
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

// Account ...
type Account struct {
	ID                uuid.UUID `gorm:"primaryKey;type:uuid;column:id;default:gen_random_uuid();"`
	Type              string
	Provider          string
	ProviderAccountID *string
	RefreshToken      *string
	AccessToken       *string
	ExpiresAt         *time.Time
	TokenType         *string
	Scope             *string
	IDToken           *string
	SessionState      string
	UserID            uuid.UUID
	User              User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// User ...
type User struct {
	ID            uuid.UUID ` gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	Name          string
	Email         string
	EmailVerified *string
	Image         *string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// Session ...
type Session struct {
	ID           uuid.UUID `gorm:"primaryKey;unique;type:uuid;column:id;default:gen_random_uuid()"`
	ExpiresAt    time.Time
	SessionToken string
	UserID       uuid.UUID
	User         User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// VerificationToken ...
type VerificationToken struct {
	Token      string `gorm:"primaryKey"`
	Identifier string
	ExpiresAt  time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// CreateUser ...
func (a *gormAdapter) CreateUser(user *adapters.User) (*adapters.User, error) {
	u := User{
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: &user.EmailVerified,
		Image:         &user.Image,
	}
	u.ID = uuid.New()

	err := a.db.Create(&u).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}
