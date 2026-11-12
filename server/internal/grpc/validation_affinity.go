package grpc

import (
	"encoding/json"
	"strings"
	"time"
)

func validationAffinityAllows(config, agentID, nodeTags string, now time.Time) bool {
	var affinity struct {
		ExecutionMode             string
		PreferredAgentID          string
		PreferredNetworkZone      string
		PreferredAgentUntilUnix   int64
		PreferredNetworkUntilUnix int64
	}
	if json.Unmarshal([]byte(config), &affinity) != nil ||
		(!strings.EqualFold(strings.TrimSpace(affinity.ExecutionMode), "risk_validation") && !strings.EqualFold(strings.TrimSpace(affinity.ExecutionMode), "credential_validation")) {
		return true
	}
	if now.Unix() < affinity.PreferredAgentUntilUnix && strings.TrimSpace(affinity.PreferredAgentID) != "" && agentID != affinity.PreferredAgentID {
		return false
	}
	if now.Unix() < affinity.PreferredNetworkUntilUnix && strings.TrimSpace(affinity.PreferredNetworkZone) != "" {
		var tags map[string]string
		if json.Unmarshal([]byte(nodeTags), &tags) != nil || !strings.EqualFold(strings.TrimSpace(tags["network_zone"]), strings.TrimSpace(affinity.PreferredNetworkZone)) {
			return false
		}
	}
	return true
}
