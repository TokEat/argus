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
}

func (r *arsenalRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
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
