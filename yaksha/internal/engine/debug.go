package engine

import (
	"sync"

	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

const maxDebugEvents = 128

// debugCollector records EXP-facing diagnostic events during one debug run.
// It intentionally does not expose or retain Yaklang VM debugger state.
type debugCollector struct {
	mu     sync.Mutex
	report protocol.DebugReport
}

func newDebugCollector() *debugCollector {
	return &debugCollector{report: protocol.DebugReport{Events: []protocol.DebugEvent{}}}
}

func (c *debugCollector) addEvent(event protocol.DebugEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.report.Events) >= maxDebugEvents {
		c.report.Truncated = true
		return
	}
	c.report.Events = append(c.report.Events, event)
}

func (c *debugCollector) result() protocol.DebugReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.DebugReport{
		Events:    append([]protocol.DebugEvent(nil), c.report.Events...),
		Truncated: c.report.Truncated,
	}
}
