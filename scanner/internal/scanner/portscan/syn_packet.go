package portscan

import (
	"encoding/binary"
	"net"
)

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20

	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
	// synWithMSSLen: IP + TCP base + MSS option (kind=2,len=4) — looks closer to a host stack than a bare 20-byte SYN.
	tcpMSSOptionLen = 4
	synPacketLen    = ipv4HeaderLen + tcpHeaderLen // bare (tests / RST)
	synProbeLen     = ipv4HeaderLen + tcpHeaderLen + tcpMSSOptionLen
)

type tcpSegment struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	DataOff uint8 // header words; 0 = default
	WithMSS bool  // append MSS 1460 (SYN probes only)
}

func buildIPv4TCP(seg tcpSegment, ttl uint8, ipID uint16) []byte {
	src := seg.SrcIP.To4()
	dst := seg.DstIP.To4()
	if src == nil || dst == nil {
		return nil
	}
	optLen := 0
	if seg.WithMSS {
		optLen = tcpMSSOptionLen
	}
	if seg.DataOff == 0 {
		seg.DataOff = uint8((tcpHeaderLen + optLen) / 4)
	}
	tcpLen := int(seg.DataOff) * 4
	if tcpLen < tcpHeaderLen+optLen {
		tcpLen = tcpHeaderLen + optLen
		seg.DataOff = uint8(tcpLen / 4)
	}
	total := ipv4HeaderLen + tcpLen
	pkt := make([]byte, total)

	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:], ipID)
	binary.BigEndian.PutUint16(pkt[6:], 0)
	pkt[8] = ttl
	pkt[9] = 6
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:ipv4HeaderLen]))

	tcp := pkt[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:], seg.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:], seg.DstPort)
	binary.BigEndian.PutUint32(tcp[4:], seg.Seq)
	binary.BigEndian.PutUint32(tcp[8:], seg.Ack)
	tcp[12] = seg.DataOff << 4
	tcp[13] = seg.Flags
	win := seg.Window
	if win == 0 {
		win = 8192
	}
	binary.BigEndian.PutUint16(tcp[14:], win)
	binary.BigEndian.PutUint16(tcp[16:], 0)
	binary.BigEndian.PutUint16(tcp[18:], 0)
	if seg.WithMSS && len(tcp) >= tcpHeaderLen+tcpMSSOptionLen {
		tcp[20] = 2    // kind MSS
		tcp[21] = 4    // length
		tcp[22] = 0x05 // 1460
		tcp[23] = 0xb4
	}
	sum := tcpChecksum(src, dst, tcp)
	binary.BigEndian.PutUint16(tcp[16:], sum)
	return pkt
}

func parseIPv4TCP(pkt []byte) (tcpSegment, bool) {
	if len(pkt) < ipv4HeaderLen+tcpHeaderLen {
		return tcpSegment{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(pkt) < ihl+tcpHeaderLen {
		return tcpSegment{}, false
	}
	if pkt[9] != 6 {
		return tcpSegment{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	if totalLen < ihl+tcpHeaderLen {
		return tcpSegment{}, false
	}
	tcp := pkt[ihl:totalLen]
	dataOff := tcp[12] >> 4
	if dataOff < 5 || int(dataOff)*4 > len(tcp) {
		return tcpSegment{}, false
	}
	return tcpSegment{
		SrcIP:   append(net.IP(nil), pkt[12:16]...),
		DstIP:   append(net.IP(nil), pkt[16:20]...),
		SrcPort: binary.BigEndian.Uint16(tcp[0:]),
		DstPort: binary.BigEndian.Uint16(tcp[2:]),
		Seq:     binary.BigEndian.Uint32(tcp[4:]),
		Ack:     binary.BigEndian.Uint32(tcp[8:]),
		Flags:   tcp[13],
		Window:  binary.BigEndian.Uint16(tcp[14:]),
		DataOff: dataOff,
	}, true
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return 0
	}
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst4[2:4]))
	sum += uint32(6)
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
