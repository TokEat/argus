package result

import (
	"context"
	"time"

	"github.com/user/dddd-server/internal/core/domain/common"
)

type Asset struct {
	ID          string
	TaskID      string
	Target      string
	IP          string
	Port        int
	Protocol    string
	URL         string
	Title       string
	Certificate string
	CreatedAt   time.Time
}

type FingerprintHit struct {
	ID        string
	TaskID    string
	Target    string
	Product   string
	Version   string
	MatchRule string
	MatchPath string
	CreatedAt time.Time
}

type Vulnerability struct {
	ID         string
	TaskID     string
	Target     string
	Name       string
	Severity   string
	SourceType string
	Evidence   string
	CreatedAt  time.Time
}

type Batch struct {
	Assets          []Asset
	Fingerprints    []FingerprintHit
	Vulnerabilities []Vulnerability
}

type Summary struct {
	TaskID             string
	AssetCount         int64
	FingerprintCount   int64
	VulnerabilityCount int64
}

type VulnerabilityFilter struct {
	TaskID string
	Page   common.Page
}

type Repository interface {
	SaveAsset(ctx context.Context, asset *Asset) error
	SaveFingerprintHit(ctx context.Context, hit *FingerprintHit) error
	SaveVulnerability(ctx context.Context, vuln *Vulnerability) error
	SaveBatch(ctx context.Context, batch *Batch) error
	GetSummary(ctx context.Context, taskID string) (*Summary, error)
	ListVulnerabilities(ctx context.Context, filter VulnerabilityFilter) ([]Vulnerability, error)
}
