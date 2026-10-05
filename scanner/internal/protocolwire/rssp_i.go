package protocolwire

import (
	"encoding/binary"
	"fmt"
)

// RSSP-I layout follows the RSD/SSE/SSR tables in WO2019091072 / EP3713194
// and the later EP4160991 table, which points the trailer at 运基信号[2010]267
// section 4.1.1.3. Multi-byte integer endianness is not stated there. The
// AMCCE 2017 FPGA paper gives the frame CRC as x^16+x^11+x^4+1 with initial
// value zero, but not the bit order, reflection, xor-out, stored endian, or a
// test vector, and one patent translation calls the SSE/SSR trailer 4 bytes.
// This check therefore does not compute a CRC. It accepts one complete frame
// whose published sizes agree:
//
//	RSD  category, type 0x80/0x81/0x82, addresses, sequence, safety length,
//	     two 4-byte SVC words, user data, 2-byte trailer.
//	     Safety length is the user length plus 8, and the buffer is exactly
//	     14 bytes plus that length. The length field selects little- or
//	     big-endian; a buffer that satisfies both is rejected.
//	SSE  20 bytes, type 0x90, 2-byte trailer.
//	SSR  25 bytes, type 0x91, data version 0x01, 2-byte trailer.
//
// Source address 0 and destination 0xFFFF are the reserved values in those
// tables. User data is capped at the 480-byte application size in the same
// tables. Identification is passive: it does not build an SSE or an RSD.
const (
	rsspIMaxUser   = 480
	rsspIRSDPrefix = 14 // header, sequence, safety length, and the 2-byte trailer
	rsspISSELen    = 20
	rsspISSRLen    = 25
)

// RSSPIInfo is one length-consistent RSSP-I frame.
type RSSPIInfo struct {
	Type     string
	Category byte
	Source   uint16
	Dest     uint16
	Sequence uint32
	hasSeq   bool
}

// Extra is the compact service detail for this frame.
func (info RSSPIInfo) Extra() string {
	if !info.hasSeq {
		return fmt.Sprintf("frame=%s cat=%d", info.Type, info.Category)
	}
	return fmt.Sprintf("frame=%s cat=%d src=%d dst=%d seq=%d", info.Type, info.Category, info.Source, info.Dest, info.Sequence)
}

// RSSPI reports whether raw is exactly one RSSP-I RSD, SSE, or SSR frame.
func RSSPI(raw []byte) (RSSPIInfo, bool) {
	if info, ok := rsspIRSD(raw); ok {
		return info, true
	}
	if info, ok := rsspIFixed(raw); ok {
		return info, true
	}
	return RSSPIInfo{}, false
}

func rsspIRSD(raw []byte) (RSSPIInfo, bool) {
	var info RSSPIInfo
	kind, ok := rsspIRSDKind(raw)
	if !ok {
		return info, false
	}
	matched := false
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		safety := int(order.Uint16(raw[10:12]))
		if safety != len(raw)-rsspIRSDPrefix || safety < 8 || safety > 8+rsspIMaxUser {
			continue
		}
		src := order.Uint16(raw[2:4])
		dst := order.Uint16(raw[4:6])
		if src == 0 || dst == 0xFFFF {
			continue
		}
		if matched {
			return RSSPIInfo{}, false
		}
		info = RSSPIInfo{
			Type:     kind,
			Category: raw[0],
			Source:   src,
			Dest:     dst,
			Sequence: order.Uint32(raw[6:10]),
			hasSeq:   true,
		}
		matched = true
	}
	return info, matched
}

func rsspIRSDKind(raw []byte) (string, bool) {
	if len(raw) < rsspIRSDPrefix+8 || len(raw) > rsspIRSDPrefix+8+rsspIMaxUser || !rsspICategory(raw[0]) {
		return "", false
	}
	switch raw[1] {
	case 0x80:
		return "rsd-a", true
	case 0x81:
		return "rsd-b", true
	case 0x82:
		return "rsd", true
	default:
		return "", false
	}
}

func rsspIFixed(raw []byte) (RSSPIInfo, bool) {
	var info RSSPIInfo
	switch len(raw) {
	case rsspISSELen:
		if !rsspICategory(raw[0]) || raw[1] != 0x90 || !rsspIAddress(raw[2:6]) {
			return info, false
		}
		info.Type = "sse"
	case rsspISSRLen:
		if !rsspICategory(raw[0]) || raw[1] != 0x91 || raw[22] != 0x01 || !rsspIAddress(raw[2:6]) {
			return info, false
		}
		info.Type = "ssr"
	default:
		return info, false
	}
	info.Category = raw[0]
	return info, true
}

func rsspICategory(b byte) bool {
	return b == 0x01 || b == 0x02
}

func rsspIAddress(raw []byte) bool {
	return !(raw[0] == 0 && raw[1] == 0) && !(raw[2] == 0xFF && raw[3] == 0xFF)
}
