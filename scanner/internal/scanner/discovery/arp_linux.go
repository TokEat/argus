//go:build linux

package discovery

import (
	"encoding/binary"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func probeRawARP(link LinkNet, ips []string, wait time.Duration) ([]string, bool) {
	if len(link.Iface.HardwareAddr) != 6 || link.SrcIP.To4() == nil || len(ips) == 0 {
		return nil, false
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, false
	}
	defer unix.Close(fd)

	var bindAddr [8]byte
	copy(bindAddr[:], link.Iface.HardwareAddr)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  link.Iface.Index,
		Halen:    6,
		Addr:     bindAddr,
	}); err != nil {
		return nil, false
	}

	want := make(map[string]struct{}, len(ips))
	for _, raw := range ips {
		ip := parseIPv4(raw)
		if ip == nil {
			continue
		}
		want[ip.String()] = struct{}{}
		frame := encodeARPRequest(link.Iface.HardwareAddr, link.SrcIP, ip)
		if frame == nil {
			continue
		}
		dst := &unix.SockaddrLinklayer{Ifindex: link.Iface.Index, Halen: 6}
		for i := 0; i < 6; i++ {
			dst.Addr[i] = 0xff
		}
		_ = unix.Sendto(fd, frame, 0, dst)
	}
	if len(want) == 0 {
		return nil, false
	}

	deadline := time.Now().Add(wait)
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	alive := make(map[string]struct{})
	buf := make([]byte, 128)
	for time.Now().Before(deadline) && len(alive) < len(want) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil || n < arpFrameLen {
			continue
		}
		_, spa, ok := decodeARPReply(buf[:n])
		if !ok {
			continue
		}
		key := spa.String()
		if _, asked := want[key]; asked {
			alive[key] = struct{}{}
		}
	}
	out := make([]string, 0, len(alive))
	for ip := range alive {
		out = append(out, ip)
	}
	return out, true
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
