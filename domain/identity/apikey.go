package identity

import "time"

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

func (r Role) CanWrite() bool {
	return r == RoleOperator || r == RoleAdmin
}

func (r Role) CanAdminister() bool {
	return r == RoleAdmin
}

type APIKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	KeyHash    string    `json:"-"`
	Role       Role      `json:"role"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
	Revoked    bool      `json:"revoked"`
}
