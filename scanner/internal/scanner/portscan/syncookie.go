package portscan

import (
	"encoding/binary"
	"net"
)

// synCookieIPv4 mirrors masscan syn_cookie_ipv4():
// SipHash-2-4 over four little-endian C unsigneds
// (ip_them, port_them, ip_me, port_me) with key {entropy, entropy}.
func synCookieIPv4(ipThem, ipMe net.IP, portThem, portMe uint16, entropy uint64) uint64 {
	them := ipv4Uint32(ipThem)
	me := ipv4Uint32(ipMe)
	var data [16]byte
	binary.LittleEndian.PutUint32(data[0:], them)
	binary.LittleEndian.PutUint32(data[4:], uint32(portThem))
	binary.LittleEndian.PutUint32(data[8:], me)
	binary.LittleEndian.PutUint32(data[12:], uint32(portMe))
	return siphash24(data[:], [2]uint64{entropy, entropy})
}

func synCookieSeq(ipThem, ipMe net.IP, portThem, portMe uint16, entropy uint64) uint32 {
	return uint32(synCookieIPv4(ipThem, ipMe, portThem, portMe, entropy))
}

func synCookieValid(ack uint32, ipThem, ipMe net.IP, portThem, portMe uint16, entropy uint64) bool {
	return synCookieSeq(ipThem, ipMe, portThem, portMe, entropy) == ack-1
}

func ipv4Uint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}
