package discovery

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
)

const (
	etherTypeARP = 0x0806
	arpHTYPE     = 1
	arpPTYPE     = 0x0800
	arpHLEN      = 6
	arpPLEN      = 4
	arpOperReq   = 1
	arpOperRep   = 2
	arpFrameLen  = 42
)

var arpWait = 2 * time.Second

var (
	rawARPProbe      = probeRawARP
	neighborARPProbe = probeNeighborARP
)

// ProbeARP sends ARP requests on each local network that contains the
// given on-link IPs. attempted is false when no probe path could run
// (no raw socket, no neighbor table); the caller should then ICMP those IPs.
func ProbeARP(onLink []string, emit func(ddout.OutputMessage)) (alive []string, attempted bool) {
	return probeARPOnNets(onLink, LocalIPv4Nets(), emit)
}

func probeARPOnNets(onLink []string, nets []LinkNet, emit func(ddout.OutputMessage)) (alive []string, attempted bool) {
	if len(onLink) == 0 || len(nets) == 0 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(onLink))
	for _, netn := range nets {
		var targets []string
		for _, raw := range onLink {
			ip := parseIPv4(raw)
			if ip == nil || !netn.Net.Contains(ip) {
				continue
			}
			if _, dup := seen[raw]; dup {
				continue
			}
			seen[raw] = struct{}{}
			targets = append(targets, raw)
		}
		if len(targets) == 0 {
			continue
		}
		found, ok := rawARPProbe(netn, targets, arpWait)
		if !ok {
			found, ok = neighborARPProbe(netn, targets, arpWait)
		}
		if !ok {
			continue
		}
		attempted = true
		for _, ip := range found {
			alive = append(alive, ip)
			if emit != nil {
				emit(ddout.OutputMessage{Type: "IPAlive", IP: ip, AdditionalMsg: "ARP"})
			}
		}
	}
	return Union(alive), attempted
}

func encodeARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()
	if len(srcMAC) != 6 || srcIP4 == nil || dstIP4 == nil {
		return nil
	}
	frame := make([]byte, arpFrameLen)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)
	binary.BigEndian.PutUint16(frame[14:16], arpHTYPE)
	binary.BigEndian.PutUint16(frame[16:18], arpPTYPE)
	frame[18] = arpHLEN
	frame[19] = arpPLEN
	binary.BigEndian.PutUint16(frame[20:22], arpOperReq)
	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP4)
	copy(frame[38:42], dstIP4)
	return frame
}

func decodeARPReply(frame []byte) (sha net.HardwareAddr, spa net.IP, ok bool) {
	if len(frame) < arpFrameLen {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[14:16]) != arpHTYPE || binary.BigEndian.Uint16(frame[16:18]) != arpPTYPE {
		return nil, nil, false
	}
	if frame[18] != arpHLEN || frame[19] != arpPLEN {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != arpOperRep {
		return nil, nil, false
	}
	mac := make(net.HardwareAddr, 6)
	copy(mac, frame[22:28])
	ip := net.IPv4(frame[28], frame[29], frame[30], frame[31]).To4()
	return mac, ip, ip != nil
}
