package engine

import (
	"encoding/json"
	"sync"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

const maxDebugEvents = 128
const maxDebugBytes = 1 << 20

// debugCollector records EXP-facing diagnostic events during one debug run.
// It intentionally does not expose or retain Yaklang VM debugger state.
type debugCollector struct {
	mu       sync.Mutex
	report   protocol.DebugReport
	bytes    int
	overflow bool
}

func newDebugCollector() *debugCollector {
	return &debugCollector{report: protocol.DebugReport{Events: []protocol.DebugEvent{}}}
}

func (c *debugCollector) addEvent(event protocol.DebugEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, _ := json.Marshal(event)
	if len(c.report.Events) >= maxDebugEvents || c.bytes+len(raw) > maxDebugBytes {
		c.report.Truncated = true
		c.overflow = true
		return
	}
	c.report.Events = append(c.report.Events, event)
	c.bytes += len(raw)
}

func (c *debugCollector) exceeded() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.overflow }

func (c *debugCollector) result() protocol.DebugReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.DebugReport{
		Events:    append([]protocol.DebugEvent(nil), c.report.Events...),
		Truncated: c.report.Truncated,
	}
}
