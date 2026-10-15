//go:build !linux

package discovery

import "time"

func probeRawARP(_ LinkNet, _ []string, _ time.Duration) ([]string, bool) {
	return nil, false
}
