package mcp

import "encoding/json"

type arsenalRecord struct {
	ID          string
	ArtifactID  string
	RuleType    string
	FileName    string
	SourceFile  string
	Path        string
	Content     string
	ContentSize int
	Hash        string
	Version     interface{}
	State       string
	UpdatedAt   string
	CreatedAt   string
	Raw         map[string]interface{}
}

func (r *arsenalRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Raw = raw
	r.ID = mapString(raw, "id", "ID")
	r.ArtifactID = mapString(raw, "artifact_id", "ArtifactID")
	r.RuleType = mapString(raw, "type", "Type", "rule_type", "RuleType")
	r.FileName = mapString(raw, "file_name", "FileName")
	r.SourceFile = mapString(raw, "source_file", "SourceFile")
	r.Path = mapString(raw, "path", "Path")
	r.Content = mapString(raw, "content", "Content")
	r.ContentSize, _ = intFromAny(firstPresent(raw, "content_size", "ContentSize"))
	r.Hash = mapString(raw, "hash", "Hash")
	r.Version = firstPresent(raw, "version", "Version")
	r.State = mapString(raw, "state", "State")
	r.UpdatedAt = mapString(raw, "updated_at", "UpdatedAt")
	r.CreatedAt = mapString(raw, "created_at", "CreatedAt")
	return nil
}

func (r arsenalRecord) StableID() string {
	return firstNonEmpty(r.ID, r.ArtifactID)
}

func (r arsenalRecord) EffectiveFileName() string {
	return firstNonEmpty(r.FileName, r.SourceFile)
}

func (r arsenalRecord) VersionInt() int {
	value, _ := intFromAny(r.Version)
	return value
}

type catalogRecord struct {
	ArtifactID    string
	RuleID        string
	Name          string
	FileName      string
	SourceFile    string
	Product       string
	TargetProduct string
	Description   string
	Tags          string
	CVE           string
	Severity      string
	RiskLevel     string
	State         string
	Hash          string
	Version       interface{}
	Enabled       bool
	Rules         []string
	Types         []string
	POCs          []string
	LinkedPOCs    interface{}
	Requirements  interface{}
	Raw           map[string]interface{}
}

func (r *catalogRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Raw = raw
	r.ArtifactID = mapString(raw, "artifact_id", "ArtifactID")
	r.RuleID = mapString(raw, "rule_id", "RuleID")
	r.Name = mapString(raw, "name", "Name")
	r.FileName = mapString(raw, "file_name", "FileName")
	r.SourceFile = mapString(raw, "source_file", "SourceFile")
	r.Product = firstNonEmpty(mapString(raw, "product", "Product"), mapString(raw, "product_name", "ProductName"))
	r.TargetProduct = mapString(raw, "target_product", "TargetProduct")
	r.Description = mapString(raw, "description", "Description")
	r.Tags = mapString(raw, "tags", "Tags")
	r.CVE = mapString(raw, "cve", "CVE")
	r.Severity = mapString(raw, "severity", "Severity")
	r.RiskLevel = mapString(raw, "risk_level", "RiskLevel")
	r.State = mapString(raw, "state", "State")
	r.Hash = firstNonEmpty(mapString(raw, "hash", "Hash"), mapString(raw, "content_hash", "ContentHash"))
	r.Version = firstPresent(raw, "version", "Version")
	r.Enabled = mapBool(raw, "enabled", "Enabled")
	r.Rules = stringSliceFromAny(firstPresent(raw, "rules", "Rules"))
	r.Types = stringSliceFromAny(firstPresent(raw, "type", "Type", "workflow_types", "WorkflowTypes"))
	r.POCs = stringSliceFromAny(firstPresent(raw, "pocs", "Pocs", "POCs", "workflow_pocs", "WorkflowPocs", "WorkflowPOCs"))
	r.LinkedPOCs = firstPresent(raw, "linked_pocs", "LinkedPocs", "LinkedPOCs")
	r.Requirements = firstPresent(raw, "requirements", "Requirements")
	return nil
}

func (r catalogRecord) EffectiveSourceFile() string {
	return firstNonEmpty(r.SourceFile, r.FileName)
}

func catalogRaw(records []catalogRecord) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		out = append(out, record.Raw)
	}
	return out
}
