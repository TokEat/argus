package ai

const (
	ArsenalTypePOC = "poc"

	SuggestionApprove = "Approve"
	SuggestionRevise  = "Revise"
	SuggestionReject  = "Reject"
)

type Config struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key,omitempty"`
	Model   string `json:"model"`
}

type PublicConfig struct {
	BaseURL      string `json:"base_url"`
	APIKey       string `json:"api_key,omitempty"`
	Model        string `json:"model"`
	HasAPIKey    bool   `json:"has_api_key"`
	APIKeyMasked string `json:"api_key_masked,omitempty"`
}

type AnalyzeRequest struct {
	TenantID string
	UserID   string
	Action   string `json:"action"` // "review", "generate", "debug"
	Type     string `json:"type"`
	FileName string `json:"file_name"`
	Content  string `json:"content"`
	Force    bool   `json:"force"`
	Context  map[string]interface{} `json:"context"` // used for debug session info
}

type Issue struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	Line       int    `json:"line,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

type DuplicateCandidate struct {
	FileName    string  `json:"file_name"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity,omitempty"`
	ContentHash string  `json:"content_hash,omitempty"`
	Reason      string  `json:"reason"`
	Score       float64 `json:"score"`
}

type AnalysisResponse struct {
	Suggestion          string               `json:"suggestion"`
	Confidence          float64              `json:"confidence"`
	Summary             string               `json:"summary"`
	Reason              string               `json:"reason"`
	Issues              []Issue              `json:"issues"`
	DuplicateCandidates []DuplicateCandidate `json:"duplicate_candidates"`
	ContentHash         string               `json:"content_hash"`
	Cached              bool                 `json:"cached"`
	Provider            string               `json:"provider"`
	Model               string               `json:"model"`
}

type llmAnalysis struct {
	Suggestion string  `json:"suggestion"`
	Confidence float64 `json:"confidence"`
	Summary    string  `json:"summary"`
	Reason     string  `json:"reason"`
	Issues     []Issue `json:"issues"`
}

func normalizeSuggestion(raw string) string {
	switch raw {
	case SuggestionApprove, SuggestionRevise, SuggestionReject:
		return raw
	default:
		return SuggestionRevise
	}
}
