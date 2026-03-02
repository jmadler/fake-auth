package store

import "context"

type User struct {
	ID             string
	Email          string
	PasswordHash   string
	DisplayName    string
	AppMetadata    map[string]interface{}
	UserMetadata   map[string]interface{}
	OrganizationID int
	EnterpriseID   int
	Role           string
}

type Role struct {
	ID          string
	Name        string
	Description string
}

type Permission struct {
	ID                        string
	Name                      string
	ResourceServerIdentifier  string
	Description               string
}

type UserStore interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	Create(ctx context.Context, u *User) error
	UpdateAppMetadata(ctx context.Context, id string, meta map[string]interface{}) error
	VerifyPassword(hash, password string) bool
}
