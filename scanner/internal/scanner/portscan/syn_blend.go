package portscan

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	mrand "math/rand"
	"time"
)

// Wire traits deliberately avoid masscan/nmap-style fixed signatures
// (XOR IP ID, narrow source-port bands, constant window/TTL, sequential sweeps).

const synRecvWait = 10 * time.Second

func synRandomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint16(b[:])
}

func synRandomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint32(b[:])
}

// synEphemeralPort picks an IANA dynamic port (49152-65535), never 0.
func synEphemeralPort() uint16 {
	const base = 49152
	const span = 65535 - base + 1
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return uint16(base + int(time.Now().UnixNano()%span))
	}
	return uint16(base + n.Int64())
}

// synSessionTTL picks a common host TTL (Linux 64 / Windows 128), not a fixed scanner constant.
func synSessionTTL() uint8 {
	if synRandomUint16()%2 == 0 {
		return 64
	}
	return 128
}

// synSessionWindow picks a plausible advertised window (not masscan's 1200 or a fixed 8192).
func synSessionWindow() uint16 {
	candidates := []uint16{29200, 64240, 65535, 16384, 8192, 4096}
	return candidates[int(synRandomUint16())%len(candidates)]
}

func synRecvWaitJittered() time.Duration {
	// Base equals masscan --wait default, plus up to ~2s jitter so dwell is not a fixed signature.
	extra := time.Duration(synRandomUint16()%2000) * time.Millisecond
	return synRecvWait + extra
}

func shuffleProbeOrder(hosts []string, ports []int, rng *mrand.Rand) []synProbe {
	out := make([]synProbe, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			out = append(out, synProbe{host: host, port: port})
		}
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

type synProbe struct {
	host string
	port int
}

// nextIPID returns a random-looking IP ID (not masscan's ip^port^seq).
func nextIPID(counter *uint32) uint16 {
	*counter += 1 + uint32(synRandomUint16()%7)
	return uint16(*counter)
}
