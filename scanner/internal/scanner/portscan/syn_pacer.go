package portscan

import "time"

// packetPacer schedules transmit slots at roughly `rate` packets/sec using a
// monotonic deadline schedule (closer to masscan pacing than time.Ticker).
type packetPacer struct {
	interval time.Duration
	next     time.Time
}

func newPacketPacer(rate int) *packetPacer {
	if rate <= 0 {
		rate = 1000
	}
	interval := time.Second / time.Duration(rate)
	if interval < time.Microsecond {
		// Sleep granularity floor; higher requested rates still send as fast as possible.
		interval = time.Microsecond
	}
	return &packetPacer{
		interval: interval,
		next:     time.Now(),
	}
}

func (p *packetPacer) wait() {
	now := time.Now()
	if delay := p.next.Sub(now); delay > 0 {
		time.Sleep(delay)
		now = time.Now()
	}
	p.next = p.next.Add(p.interval)
	// If we fell far behind (GC/scheduling), resync instead of bursting a huge backlog.
	if lag := now.Sub(p.next); lag > 10*p.interval {
		p.next = now.Add(p.interval)
	}
}
