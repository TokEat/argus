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
	CodeHash      string    `gorm:"primaryKey"`
	ClientID      string    `gorm:"index;not null"`
	RedirectURI   string    `gorm:"not null"`
	Resource      string    `gorm:"not null"`
	CodeChallenge string    `gorm:"not null"`
	UserID        string    `gorm:"not null"`
	TenantID      string    `gorm:"index;not null"`
	Role          string    `gorm:"not null"`
	RoleBase      string    `gorm:"default:''"`
	ExpAuthorized bool      `gorm:"default:false"`
	ExpiresAt     time.Time `gorm:"index;not null"`
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

// TenantMCPSettings is the per-tenant MCP enable flag. Missing row means enabled.
type TenantMCPSettings struct {
	TenantID  string    `gorm:"primaryKey;size:128"`
	Enabled   bool      `gorm:"not null"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	UpdatedBy string    `gorm:"size:64;default:''"`
}

func (TenantMCPSettings) TableName() string { return "tenant_mcp_settings" }

// OAuthTenantClientBlock disables one OAuth client for one tenant without deleting the global row.
type OAuthTenantClientBlock struct {
	TenantID  string    `gorm:"primaryKey;size:128"`
	ClientID  string    `gorm:"primaryKey;size:128"`
	BlockedAt time.Time `gorm:"autoCreateTime"`
	ActorID   string    `gorm:"size:64;default:''"`
}

func (OAuthTenantClientBlock) TableName() string { return "oauth_tenant_client_blocks" }

// MCPAdminEvent records tenant-admin MCP governance actions, not tools/call traffic.
type MCPAdminEvent struct {
	ID        string    `gorm:"primaryKey;size:64"`
	TenantID  string    `gorm:"index;size:128;not null"`
	ActorID   string    `gorm:"index;size:64;default:''"`
	Action    string    `gorm:"index;size:64;not null"`
	ClientID  string    `gorm:"size:128;default:''"`
	Details   string    `gorm:"type:text"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (MCPAdminEvent) TableName() string { return "mcp_admin_events" }
