package db

import "time"

// OAuthClient is a public OAuth client allowed to use the MCP authorization server.
type OAuthClient struct {
	ClientID     string    `gorm:"primaryKey"`
	RedirectURIs string    `gorm:"type:text;not null"`
	Public       bool      `gorm:"default:true"`
	TenantID     string    `gorm:"index;default:''"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

// OAuthAuthorizationCode stores a hashed, single-use authorization code.
type OAuthAuthorizationCode struct {
	CodeHash      string     `gorm:"primaryKey"`
	ClientID      string     `gorm:"index;not null"`
	RedirectURI   string     `gorm:"not null"`
	Resource      string     `gorm:"not null"`
	CodeChallenge string     `gorm:"not null"`
	UserID        string     `gorm:"not null"`
	TenantID      string     `gorm:"index;not null"`
	Role          string     `gorm:"not null"`
	RoleBase      string     `gorm:"default:''"`
	ExpAuthorized bool       `gorm:"default:false"`
	ExpiresAt     time.Time  `gorm:"index;not null"`
	UsedAt        *time.Time
	CreatedAt     time.Time `gorm:"autoCreateTime"`
}

func (OAuthAuthorizationCode) TableName() string { return "oauth_authorization_codes" }

// OAuthRefreshToken stores a hashed refresh token. Reuse after revoke invalidates the family.
type OAuthRefreshToken struct {
	TokenHash     string     `gorm:"primaryKey"`
	ClientID      string     `gorm:"index;not null"`
	UserID        string     `gorm:"index;not null"`
	TenantID      string     `gorm:"index;not null"`
	Role          string     `gorm:"not null"`
	RoleBase      string     `gorm:"default:''"`
	ExpAuthorized bool       `gorm:"default:false"`
	Resource      string     `gorm:"not null"`
	ExpiresAt     time.Time  `gorm:"index;not null"`
	RevokedAt     *time.Time `gorm:"index"`
	CreatedAt     time.Time  `gorm:"autoCreateTime"`
}

func (OAuthRefreshToken) TableName() string { return "oauth_refresh_tokens" }
