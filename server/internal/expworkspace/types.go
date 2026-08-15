package expworkspace

import (
	"encoding/json"
	"time"
)

const (
	MaxSourceBytes  = 1 << 20
	MaxAssetBytes   = 1 << 20
	MaxDependencies = 16
	MaxAssets       = 32
)

type DependencyInput struct {
	ExpID        string `json:"exp_id"`
	Revision     int    `json:"revision"`
	SourceSHA256 string `json:"source_sha256"`
}

type AssetRefInput struct {
	AssetID string `json:"asset_id"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

type CreateRevisionInput struct {
	Source       string            `json:"source"`
	Dependencies []DependencyInput `json:"dependencies"`
	Assets       []AssetRefInput   `json:"assets"`
}

type DraftPackageInput struct {
	Source       string            `json:"source"`
	Dependencies []DependencyInput `json:"dependencies"`
	Assets       []AssetRefInput   `json:"assets"`
	TestCases    []TestCaseInput   `json:"test_cases,omitempty"`
}

type CreateTestedRevisionInput struct {
	DraftPackageInput
	TestReceipt string `json:"test_receipt"`
}

type DraftTestResult struct {
	RuntimeResponse RuntimeResponse `json:"runtime_response"`
	TestReceipt     string          `json:"test_receipt"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

type SealedDependency struct {
	ExpID        string `json:"exp_id"`
	Revision     int    `json:"revision"`
	SourceSHA256 string `json:"source_sha256"`
	Script       string `json:"script"`
}

type SealedAsset struct {
	AssetID  string `json:"asset_id"`
	SHA256   string `json:"sha256"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type SealedPackage struct {
	ExpID                    string             `json:"exp_id"`
	ExpStatus                string             `json:"exp_status"`
	RiskLevel                string             `json:"risk_level"`
	RiskWaiverActive         bool               `json:"risk_waiver_active"`
	RequiresRiskConfirmation bool               `json:"requires_risk_confirmation"`
	DeprecatedDependency     string             `json:"deprecated_dependency,omitempty"`
	Revision                 int                `json:"revision"`
	SourceSHA256             string             `json:"source_sha256"`
	Script                   string             `json:"script"`
	DependencyRefs           []DependencyInput  `json:"dependency_refs"`
	AssetRefs                []AssetRefInput    `json:"asset_refs"`
	Dependencies             []SealedDependency `json:"dependencies"`
	Assets                   []SealedAsset      `json:"assets"`
	TestCases                []json.RawMessage  `json:"test_cases,omitempty"`
	TestCasesSHA256          string             `json:"test_cases_sha256,omitempty"`
}

type RuntimeRequest struct {
	ID             string             `json:"id"`
	Action         string             `json:"action"`
	Script         string             `json:"script"`
	Params         map[string]any     `json:"params,omitempty"`
	TimeoutMS      int                `json:"timeout_ms,omitempty"`
	TestCases      []json.RawMessage  `json:"test_cases,omitempty"`
	ExpID          string             `json:"exp_id"`
	Revision       int                `json:"revision"`
	SourceSHA256   string             `json:"source_sha256"`
	Dependencies   []SealedDependency `json:"dependencies,omitempty"`
	Assets         []SealedAsset      `json:"assets,omitempty"`
	NetworkTargets []string           `json:"network_targets,omitempty"`
	Egress         map[string]any     `json:"egress,omitempty"`
	ValidationMode string             `json:"validation_mode,omitempty"`
}

type RuntimeResponse map[string]any

type RunInput struct {
	Action         string         `json:"action"`
	SourceSHA256   string         `json:"source_sha256"`
	Params         map[string]any `json:"params,omitempty"`
	TimeoutMS      int            `json:"timeout_ms,omitempty"`
	NetworkTargets []string       `json:"network_targets,omitempty"`
	Egress         EgressInput    `json:"egress"`
	RiskConfirmed  bool           `json:"risk_confirmed,omitempty"`
}

type EgressInput struct {
	Mode          string `json:"mode"`
	SOCKS5Proxy   string `json:"socks5_proxy,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	RiskConfirmed bool   `json:"risk_confirmed,omitempty"`
}

type RunResult struct {
	RunID      string          `json:"run_id"`
	Response   RuntimeResponse `json:"response"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
}
