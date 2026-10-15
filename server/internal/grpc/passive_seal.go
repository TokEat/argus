package grpc

import (
	"encoding/json"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/subdomainpassive"
	"gorm.io/gorm"
)

// applyPassiveClaimSeal best-effort seals fresh Server-side passive results
// into the config being handed to a capable Agent. It covers attempts that
// reached dispatch without pre-collection sealing (hold timeout, retries,
// recovery replays); failures keep the unsealed config so the Agent falls
// back to today's agent-side collection.
func applyPassiveClaimSeal(tx *gorm.DB, agentTags string, sub db.SubTask, config []byte) []byte {
	if len(config) == 0 {
		return config
	}
	var chunkTargets []string
	if err := json.Unmarshal([]byte(sub.ChunkTargets), &chunkTargets); err != nil {
		return config
	}
	return subdomainpassive.ClaimSeal(tx, agentTags, chunkTargets, config)
}
