package rule

import (
	"context"
	"time"

	"github.com/P0lar1ght/argus/server/internal/core/domain/common"
)

type BundleStatus string
type ArtifactType string

const (
	BundleStatusDraft    BundleStatus = "Draft"
	BundleStatusActive   BundleStatus = "Active"
	BundleStatusArchived BundleStatus = "Archived"
)

const (
	ArtifactTypeFinger   ArtifactType = "finger"
	ArtifactTypeWorkflow ArtifactType = "workflow"
	ArtifactTypeDir      ArtifactType = "dir"
	ArtifactTypePOC      ArtifactType = "poc"
)

type Bundle struct {
	Version   string
	Status    BundleStatus
	Hash      string
	Artifacts []Artifact
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Artifact struct {
	ID        string
	Bundle    string
	Type      ArtifactType
	FileName  string
	Hash      string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ArtifactFilter struct {
	Bundle string
	Types  []ArtifactType
	Page   common.Page
}

type Repository interface {
	SaveBundle(ctx context.Context, bundle *Bundle) error
	GetBundle(ctx context.Context, version string) (*Bundle, error)
	GetActiveBundle(ctx context.Context) (*Bundle, error)
	ListArtifacts(ctx context.Context, filter ArtifactFilter) ([]Artifact, error)
}
