package protocolwire

import (
	"encoding/binary"
	"fmt"
)

// RSSP-II ALEPKT header from the public BJMT RsspII parser, which follows
// 运基信号[2010]267 / UNISIG Subset-098. The header is 10 bytes, big-endian:
//
//	0-1 length of the remaining packet
//	2   version 0x01
//	3   application type
//	4-5 sequence number
//	6   N/R flag, 0 or 1
//	7   packet type
//	8-9 CRC-16/CCITT-FALSE of bytes 0-7
//
// Keepalive types 0xFE and 0xFF carry an empty body and no checksum.
const (
	rsspIIHeaderLen    = 10
	rsspIIVersion      = 0x01
	rsspIIMinPacketLen = 8
	rsspIIMaxPacketLen = 16*1024 - 2
)

// RSSPIIInfo is a CRC-checked or keepalive RSSP-II ALE header.
type RSSPIIInfo struct {
	Type        string
	Application byte
	Sequence    uint16
	Normal      bool
}

// Extra is the compact service detail for this header.
func (info RSSPIIInfo) Extra() string {
	link := "redundant"
	if info.Normal {
		link = "normal"
	}
	return fmt.Sprintf("ale=%s app=%d link=%s seq=%d", info.Type, info.Application, link, info.Sequence)
}

// RSSPIIALE reports whether raw begins with one RSSP-II ALE packet.
// Identification is passive: it does not build a connection request, an AU1,
// or any other safety-association frame.
func RSSPIIALE(raw []byte) (RSSPIIInfo, bool) {
	var info RSSPIIInfo
	if len(raw) < rsspIIHeaderLen {
		return info, false
	}
	packetLen := int(binary.BigEndian.Uint16(raw[:2]))
	if packetLen < rsspIIMinPacketLen || packetLen > rsspIIMaxPacketLen || raw[2] != rsspIIVersion || raw[6] > 1 {
		return info, false
	}
	name, checkCRC, ok := rsspIIPacketType(raw[7])
	if !ok {
		return info, false
	}
	if checkCRC {
		if crc16CCITTFalse(raw[:8]) != binary.BigEndian.Uint16(raw[8:10]) {
			return info, false
		}
	} else if packetLen != rsspIIMinPacketLen {
		return info, false
	}
	info = RSSPIIInfo{
		Type:        name,
		Application: raw[3],
		Sequence:    binary.BigEndian.Uint16(raw[4:6]),
		Normal:      raw[6] == 1,
	}
	return info, true
}

func rsspIIPacketType(kind byte) (name string, checkCRC bool, ok bool) {
	switch kind {
	case 0x01:
		return "cr", true, true
	case 0x02:
		return "cc", true, true
	case 0x03:
		return "dt", true, true
	case 0x04:
		return "di", true, true
	case 251:
		return "n2r", true, true
	case 253:
		return "r2n", true, true
	case 254:
		return "kana", false, true
	case 255:
		return "kaa", false, true
	default:
		return "", false, false
	}
}

// crc16CCITTFalse is CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF,
// refin/refout false, xorout 0. The BJMT parser checks bytes
// 00 1E 01 1A 00 00 01 01 as 0x1089.
func crc16CCITTFalse(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
