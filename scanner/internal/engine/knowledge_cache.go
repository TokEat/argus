package engine

import (
	"fmt"
	"strings"
	"sync"
)

const knowledgeCacheCapacity = 3

type knowledgeSnapshot struct {
	packageHash   string
	ruleVersion   string
	fingerprintDB []FingerPEntity
	workflowDB    map[string]WorkFlowEntity
	dirDB         map[string][]string
}

type knowledgeCacheKey struct{ packageHash, ruleVersion string }

type knowledgeCacheEntry struct {
	snapshot *knowledgeSnapshot
	err      error
	ready    chan struct{}
}

var knowledgeCache = struct {
	sync.Mutex
	entries map[knowledgeCacheKey]*knowledgeCacheEntry
	lru     []knowledgeCacheKey
}{entries: make(map[knowledgeCacheKey]*knowledgeCacheEntry)}

// knowledge loaders are seams for deterministic cache tests. Production keeps
// the complete legacy parsers, including all three rule sources.
var (
	knowledgeFingerLoader   = loadFingerDB
	knowledgeWorkflowLoader = loadWorkflowDB
	knowledgeDirLoader      = loadDirDB
)

func knowledgeIdentityEnabled(cfg Config) (bool, error) {
	hashPresent := cfg.KnowledgePackageHash != ""
	versionPresent := cfg.KnowledgeRuleVersion != ""
	if !hashPresent && !versionPresent {
		return false, nil
	}
	if !cfg.RuleFilesOnly || !hashPresent || !versionPresent ||
		!validKnowledgeIdentityPart(cfg.KnowledgePackageHash) || !validKnowledgeIdentityPart(cfg.KnowledgeRuleVersion) {
		return false, fmt.Errorf("invalid verified knowledge package identity")
	}
	return true, nil
}

func validKnowledgeIdentityPart(value string) bool {
	if value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (sc *ScanContext) loadKnowledgeSnapshot() (*knowledgeSnapshot, error) {
	fingerDB, err := knowledgeFingerLoader(sc.Config)
	if err != nil {
		return nil, err
	}
	workflowDB, err := knowledgeWorkflowLoader(sc.Config)
	if err != nil {
		return nil, err
	}
	dirDB, err := knowledgeDirLoader(sc.Config)
	if err != nil {
		return nil, err
	}
	return &knowledgeSnapshot{packageHash: sc.Config.KnowledgePackageHash, ruleVersion: sc.Config.KnowledgeRuleVersion, fingerprintDB: fingerDB, workflowDB: workflowDB, dirDB: dirDB}, nil
}

func touchKnowledgeCacheLocked(key knowledgeCacheKey) {
	for i, existing := range knowledgeCache.lru {
		if existing == key {
			knowledgeCache.lru = append(knowledgeCache.lru[:i], knowledgeCache.lru[i+1:]...)
			break
		}
	}
	knowledgeCache.lru = append(knowledgeCache.lru, key)
}

func (sc *ScanContext) cachedKnowledgeSnapshot() (*knowledgeSnapshot, error) {
	key := knowledgeCacheKey{sc.Config.KnowledgePackageHash, sc.Config.KnowledgeRuleVersion}
	knowledgeCache.Lock()
	if entry := knowledgeCache.entries[key]; entry != nil {
		touchKnowledgeCacheLocked(key)
		knowledgeCache.Unlock()
		<-entry.ready
		return entry.snapshot, entry.err
	}
	entry := &knowledgeCacheEntry{ready: make(chan struct{})}
	knowledgeCache.entries[key] = entry
	touchKnowledgeCacheLocked(key)
	knowledgeCache.Unlock()

	snapshot, err := sc.loadKnowledgeSnapshot()
	knowledgeCache.Lock()
	entry.snapshot, entry.err = snapshot, err
	if err != nil {
		delete(knowledgeCache.entries, key)
		for i, existing := range knowledgeCache.lru {
			if existing == key {
				knowledgeCache.lru = append(knowledgeCache.lru[:i], knowledgeCache.lru[i+1:]...)
				break
			}
		}
	} else {
		for len(knowledgeCache.lru) > knowledgeCacheCapacity {
			evictAt := -1
			for i, candidate := range knowledgeCache.lru {
				candidateEntry := knowledgeCache.entries[candidate]
				select {
				case <-candidateEntry.ready:
					evictAt = i
				default:
				}
				if evictAt >= 0 {
					break
				}
			}
			if evictAt < 0 {
				break // temporarily exceed the bound while all entries are building
			}
			evicted := knowledgeCache.lru[evictAt]
			knowledgeCache.lru = append(knowledgeCache.lru[:evictAt], knowledgeCache.lru[evictAt+1:]...)
			delete(knowledgeCache.entries, evicted)
		}
	}
	close(entry.ready)
	knowledgeCache.Unlock()
	return snapshot, err
}

func cloneFingerDB(src []FingerPEntity) []FingerPEntity {
	if src == nil {
		return nil
	}
	dst := make([]FingerPEntity, len(src))
	for i, finger := range src {
		dst[i] = finger
		dst[i].Rule = append([]RuleData(nil), finger.Rule...)
	}
	return dst
}

func cloneWorkflowDB(src map[string]WorkFlowEntity) map[string]WorkFlowEntity {
	if src == nil {
		return nil
	}
	dst := make(map[string]WorkFlowEntity, len(src))
	for key, workflow := range src {
		workflow.PocsName = append([]string(nil), workflow.PocsName...)
		dst[key] = workflow
	}
	return dst
}
