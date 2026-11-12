package httpx

import (
	"context"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/httpx/runner"
)

// ProbeSession gives each HTTP input its own request budget.  It intentionally
// reserves initial inputs without starting their timers: the clock starts only
// when httpx is about to analyse that input.
type ProbeSession struct {
	parent  context.Context
	timeout time.Duration
	visits  URLVisitSet

	mu     sync.Mutex
	closed bool
	slots  map[string]*probeSlot
}

// URLVisitSet atomically records HTTP URLs that have entered a probe pass.
// It can be shared by explicitly related sessions, while the default session
// constructor keeps the visit scope private to that session.
type URLVisitSet interface {
	TryVisitHTTPURL(string) bool
}

type memoryURLVisitSet struct {
	mu   sync.Mutex
	urls map[string]struct{}
}

func newMemoryURLVisitSet() *memoryURLVisitSet {
	return &memoryURLVisitSet{urls: make(map[string]struct{})}
}

func (s *memoryURLVisitSet) TryVisitHTTPURL(raw string) bool {
	if s == nil {
		return true
	}
	key := canonicalProbeURL(raw)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.urls[key]; exists {
		return false
	}
	s.urls[key] = struct{}{}
	return true
}

type probeSlot struct {
	ctx                context.Context
	cancel             context.CancelFunc
	started            bool
	pendingCompletions int
}

// NewProbeSession creates an HTTP probe session. A nil parent behaves like a
// background context, preserving the package-level helper API.
func NewProbeSession(parent context.Context, timeout int) *ProbeSession {
	return NewProbeSessionWithURLVisits(parent, timeout, nil)
}

// NewProbeSessionWithURLVisits creates a session with an optional visit scope.
// A nil visit set is replaced with a private, concurrency-safe in-memory set.
func NewProbeSessionWithURLVisits(parent context.Context, timeout int, visits URLVisitSet) *ProbeSession {
	if parent == nil {
		parent = context.Background()
	}
	if isNilURLVisitSet(visits) {
		visits = newMemoryURLVisitSet()
	}
	return &ProbeSession{
		parent:  parent,
		timeout: time.Duration(sanitizeTimeout(timeout)) * time.Second,
		visits:  visits,
		slots:   make(map[string]*probeSlot),
	}
}

func isNilURLVisitSet(visits URLVisitSet) bool {
	if visits == nil {
		return true
	}
	value := reflect.ValueOf(visits)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Close cancels every started target budget. It is safe to call more than once.
func (s *ProbeSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, slot := range s.slots {
		if slot.cancel != nil {
			slot.cancel()
		}
	}
}

func canonicalProbeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return strings.TrimSpace(raw)
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u.String()
}

func (s *ProbeSession) reserve(raw string) *probeSlot {
	key := canonicalProbeURL(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot := s.slots[key]; slot != nil {
		return slot
	}
	slot := &probeSlot{}
	s.slots[key] = slot
	return slot
}

func (s *ProbeSession) lookup(raw string) *probeSlot {
	key := canonicalProbeURL(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.slots[key]
}

// TargetContext is supplied to Runner. It starts the input's independent
// deadline lazily, immediately before Runner creates a request.
func (s *ProbeSession) TargetContext(raw string) context.Context {
	if s == nil {
		return context.Background()
	}
	key := canonicalProbeURL(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[key]
	if slot == nil {
		slot = &probeSlot{}
		s.slots[key] = slot
	}
	if !slot.started {
		if s.closed {
			slot.ctx, slot.cancel = context.WithCancel(s.parent)
			slot.cancel()
		} else {
			slot.ctx, slot.cancel = context.WithTimeout(s.parent, s.timeout)
		}
		slot.started = true
	}
	slot.pendingCompletions++
	return slot.ctx
}

func (s *ProbeSession) completeIfActive(raw string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[canonicalProbeURL(raw)]
	if s.closed || s.parent.Err() != nil || slot == nil || (slot.started && slot.ctx.Err() != nil) {
		return false
	}
	if slot.pendingCompletions > 0 {
		slot.pendingCompletions--
	}
	return true
}

// Err reports a target deadline only when an attempted probe did not produce
// a usable response. Completed targets are not reclassified merely because
// their deadline expires while another independent target is still running.
func (s *ProbeSession) Err() error {
	if s == nil {
		return nil
	}
	if err := s.parent.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[*probeSlot]struct{}, len(s.slots))
	for _, slot := range s.slots {
		if _, ok := seen[slot]; ok {
			continue
		}
		seen[slot] = struct{}{}
		if slot.started && slot.pendingCompletions > 0 && slot.ctx.Err() != nil {
			return slot.ctx.Err()
		}
	}
	return nil
}

func (s *ProbeSession) isActive(raw string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.parent.Err() != nil {
		return false
	}
	slot := s.slots[canonicalProbeURL(raw)]
	return slot == nil || !slot.started || slot.ctx.Err() == nil
}

func (s *ProbeSession) markExpiredFollowUp(raw string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := s.slots[canonicalProbeURL(raw)]
	if slot != nil && slot.started && slot.ctx.Err() != nil && slot.pendingCompletions == 0 {
		slot.pendingCompletions = 1
	}
}

func (s *ProbeSession) reserveInputs(urls []string) []string {
	reserved := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		key := canonicalProbeURL(raw)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		s.reserve(raw)
		reserved = append(reserved, raw)
	}
	return reserved
}

func (s *ProbeSession) reserveUnvisitedURLs(urls []string) []string {
	if s == nil || s.visits == nil {
		return nil
	}
	reserved := make([]string, 0, len(urls))
	for _, raw := range urls {
		if s.visits.TryVisitHTTPURL(canonicalProbeURL(raw)) {
			reserved = append(reserved, raw)
		}
	}
	return reserved
}

// alias makes an internally discovered URL consume its source input's budget.
// A previously reserved independent input always wins, so one initial target
// cannot accidentally shorten another target's budget.
func (s *ProbeSession) alias(raw, source string) {
	if s == nil || raw == "" || source == "" {
		return
	}
	aliasKey := canonicalProbeURL(raw)
	sourceKey := canonicalProbeURL(source)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.slots[aliasKey]; exists {
		return
	}
	sourceSlot := s.slots[sourceKey]
	if sourceSlot == nil {
		sourceSlot = &probeSlot{}
		s.slots[sourceKey] = sourceSlot
	}
	s.slots[aliasKey] = sourceSlot
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func safeLocation(source, location string) string {
	base, err := url.Parse(source)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return ""
	}
	destination := base.ResolveReference(ref)
	if destination.Scheme == "" || destination.Host == "" || !strings.EqualFold(base.Hostname(), destination.Hostname()) {
		return ""
	}
	sameEndpoint := strings.EqualFold(base.Scheme, destination.Scheme) && effectivePort(base) == effectivePort(destination)
	upgrade := strings.EqualFold(base.Scheme, "http") && effectivePort(base) == "80" && strings.EqualFold(destination.Scheme, "https") && effectivePort(destination) == "443"
	if !sameEndpoint && !upgrade {
		return ""
	}
	destination.Fragment = ""
	if destination.Path == "" {
		destination.Path = "/"
	}
	return destination.String()
}

func (s *ProbeSession) sourceFor(resp runner.Result) string {
	for _, raw := range []string{resp.Input, resp.URL, resp.FinalURL} {
		if raw != "" && s.lookup(raw) != nil {
			return raw
		}
	}
	if resp.Input != "" {
		s.reserve(resp.Input)
		return resp.Input
	}
	return resp.URL
}

func (s *ProbeSession) wrapCallback(callback func(runner.Result)) func(runner.Result) {
	return func(resp runner.Result) {
		source := s.sourceFor(resp)
		// Register all safe aliases before checking expiry, so a result arriving
		// exactly at the deadline cannot let a later pass reset its budget.
		s.alias(resp.URL, source)
		s.alias(resp.FinalURL, source)
		if location := safeLocation(resp.FinalURL, resp.Location); location != "" {
			s.alias(location, source)
		} else if location := safeLocation(resp.URL, resp.Location); location != "" {
			s.alias(location, source)
		}
		if s.completeIfActive(source) {
			if callback != nil {
				callback(resp)
			}
		}
	}
}

func (s *ProbeSession) registerNextCheckTargets(targets []runner.NextCheckTarget) []string {
	urls := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.URL == "" || target.SourceInput == "" {
			continue
		}
		s.alias(target.URL, target.SourceInput)
		if s.isActive(target.URL) {
			urls = append(urls, target.URL)
		} else {
			s.markExpiredFollowUp(target.URL)
		}
	}
	return RemoveDuplicateElement(urls)
}
