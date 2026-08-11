// Package taskstore creates the task-private response stores used by scans.
package taskstore

import (
	"fmt"
	"strings"

	"dddd/scanner/structs"
	"dddd/scanner/utils"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

const smallTaskLimit = 8

// Stores are the three response stores owned by one scan context. All stores
// use the same immutable storage decision.
type Stores struct {
	Body   *hybrid.HybridMap
	Header *hybrid.HybridMap
	Banner *hybrid.HybridMap
}

var newHybridMap = hybrid.New

// UsesMemory reports whether cfg is a bounded, non-expanding task whose
// response data may remain in memory. Unknown input and every expandable
// source deliberately fall back to disk.
func UsesMemory(cfg structs.Config) bool {
	if len(cfg.Targets) == 0 || strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "risk_validation") {
		return true
	}
	if len(cfg.Targets) > smallTaskLimit || cfg.Subdomain || !cfg.NoDirSearch || !cfg.NoHostBind {
		return false
	}
	for _, target := range cfg.Targets {
		switch utils.GetInputType(target) {
		case structs.TypeURL, structs.TypeIPPort, structs.TypeDomainPort:
		default:
			return false
		}
	}
	return true
}

// New allocates three task-private response stores using one storage decision.
// If any allocation fails, every already-created store is closed.
func New(cfg structs.Config) (*Stores, error) {
	options := hybrid.DefaultDiskOptions
	if UsesMemory(cfg) {
		options = hybrid.DefaultMemoryOptions
	}

	body, err := newHybridMap(options)
	if err != nil {
		return nil, fmt.Errorf("create body response store: %w", err)
	}
	header, err := newHybridMap(options)
	if err != nil {
		body.Close()
		return nil, fmt.Errorf("create header response store: %w", err)
	}
	banner, err := newHybridMap(options)
	if err != nil {
		body.Close()
		header.Close()
		return nil, fmt.Errorf("create banner response store: %w", err)
	}
	return &Stores{Body: body, Header: header, Banner: banner}, nil
}
