package intranet

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

func mustHex(raw string) []byte {
	data, _ := hex.DecodeString(raw)
	return data
}

func ldapBindReq() []byte {
	// nmap LDAPBindReq: anonymous bind
	return []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x02, 0x04, 0x00, 0x80, 0x00}
}

func ldapRootDSE() []byte {
	// nmap LDAPSearchReq
	return []byte{
		0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x07, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24,
		0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x64, 0x01,
		0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
		0x30, 0x84, 0x00, 0x00, 0x00, 0x00,
	}
}

func kerberosASREQ() []byte {
	// nmap TCP Kerberos probe (includes 4-byte length)
	return []byte{
		0x00, 0x00, 0x00, 0x71, 0x6a, 0x81, 0x6e, 0x30, 0x81, 0x6b, 0xa1, 0x03, 0x02, 0x01, 0x05,
		0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa4, 0x81, 0x5e, 0x30, 0x5c, 0xa0, 0x07, 0x03, 0x05, 0x00,
		0x50, 0x80, 0x00, 0x10, 0xa2, 0x04, 0x1b, 0x02, 'N', 'M', 0xa3, 0x17, 0x30, 0x15, 0xa0,
		0x03, 0x02, 0x01, 0x00, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x06, 'k', 'r', 'b', 't', 'g', 't',
		0x1b, 0x02, 'N', 'M', 0xa5, 0x11, 0x18, 0x0f, '1', '9', '7', '0', '0', '1', '0', '1',
		'0', '0', '0', '0', '0', '0', 'Z', 0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9, 0xa8,
		0x17, 0x30, 0x15, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17,
		0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02,
	}
}

func rpcPortmapNull() []byte {
	return rpcCall(100000, 2, 0)
}

func nfsNull() []byte {
	return rpcCall(100003, 3, 0)
}

func rpcCall(prog, vers, proc uint32) []byte {
	body := make([]byte, 40)
	binary.BigEndian.PutUint32(body[0:], 0x72fe1d13)
	binary.BigEndian.PutUint32(body[4:], 0)
	binary.BigEndian.PutUint32(body[8:], 2)
	binary.BigEndian.PutUint32(body[12:], prog)
	binary.BigEndian.PutUint32(body[16:], vers)
	binary.BigEndian.PutUint32(body[20:], proc)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0x80000000|uint32(len(body)))
	return append(hdr, body...)
}

func netbiosSessionReq() []byte {
	called := netbiosEncode("*SMBSERVER")
	calling := netbiosEncode("ARGUS")
	payload := append([]byte{0x20}, called...)
	payload = append(payload, 0x20)
	payload = append(payload, calling...)
	out := []byte{0x81, 0x00, byte(len(payload) >> 8), byte(len(payload))}
	return append(out, payload...)
}

func netbiosEncode(name string) []byte {
	padded := make([]byte, 16)
	copy(padded, []byte(name))
	for i := len(name); i < 15; i++ {
		padded[i] = ' '
	}
	out := make([]byte, 32)
	for i := 0; i < 16; i++ {
		out[i*2] = 'A' + (padded[i] >> 4)
		out[i*2+1] = 'A' + (padded[i] & 0x0f)
	}
	return out
}

func dnsVersionBindTCP() []byte {
	return []byte{
		0x00, 0x1e, 0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
	}
}

func mqttConnect() []byte {
	return []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x04, 'n', 'm', 'a', 'p'}
}

func amqpHeader() []byte {
	return []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
}

func dubboStatus() []byte {
	return []byte("status\r\n")
}

func epmdNames() []byte {
	return []byte{0x00, 0x01, 0x6e}
}

func rocketMQRequest(code int) []byte {
	header := map[string]interface{}{
		"code":     code,
		"language": "JAVA",
		"version":  395,
		"opaque":   code,
		"flag":     0,
	}
	encoded, _ := json.Marshal(header)
	frameLen := 4 + len(encoded)
	out := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(encoded)))
	copy(out[8:], encoded)
	return out
}

func weblogicT3Hello() []byte {
	return []byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
}

func weblogicIIOPProbe() []byte {
	return []byte("GIOP\x01\x00\x01\x00$\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00abcdef\x00\x00\x04\x00\x00\x00get\x00\x00\x00\x00\x00")
}

func jbossRemotingProbe() []byte {
	return nil
}

func modbusDeviceID() []byte {
	return []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2b, 0x0e, 0x01, 0x00}
}

func dnp3LinkStatus() []byte {
	return mustHex("056405060100000055c4")
}

func s7COTPConnectionRequest() []byte {
	return mustHex("0300001611e00000000100c0010ac1020100c2020102")
}

func s7SetupCommunication() []byte {
	return mustHex("0300001902f08032010000000000080000f0000001000101e0")
}

func etherNetIPListIdentity() []byte {
	return mustHex("630000000000000000000000000000000000000000000000")
}

func atgInventory() []byte {
	return []byte("\x01I20100\n")
}

func melsecQBinaryRead() []byte {
	return mustHex("5700000011000000000000ffff0300001c001008000000000000000000000104010001000000")
}

func finsNodeAddressRequest() []byte {
	return mustHex("46494e530000000c00000000000000000000000000")
}

func crimsonServiceProbe() []byte {
	return mustHex("00040116")
}

func iec104StartDTActivation() []byte {
	return mustHex("680407000000")
}

func msmqPing() []byte {
	return mustHex("10010000000000000000000000000000")
}

func sapP4NIPing() []byte {
	return []byte("NI_PING\x00")
}

func pcworxProbe() []byte {
	return []byte("\x01\x01\x00\x1a\x00\x00\x00\x00x\x80\x00\x03\x00\x0cIBETH01N0_M\x00")
}

func codesysProbe() []byte {
	return []byte("\x44\x6d\x64\x54\x00\x00\x00\x17\x00\x00\x00\x01\x00\x00\x00\x00\x11\x11\x00\xff\x01\xff\x13")
}

func proconosProbe() []byte {
	return []byte{0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee}
}

func postgresStartup() []byte {
	params := []byte("user\x00argus\x00database\x00postgres\x00\x00")
	body := append([]byte{0x00, 0x03, 0x00, 0x00}, params...)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(out)))
	copy(out[4:], body)
	return out
}

func rsyncHello() []byte {
	return []byte("@RSYNCD: 31.0\n")
}

func svnHello() []byte {
	return []byte("( 2 ( edit-pipeline ) ) \n")
}

func stompConnect() []byte {
	return []byte("CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\n\n\x00")
}

func cassandraOptions() []byte {
	// Native protocol v4 OPTIONS request: version, flags, stream, opcode,
	// and a zero-length body.
	return []byte{0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00}
}

func clickhouseHello() []byte {
	return []byte{
		0x00, 0x11, 'C', 'l', 'i', 'c', 'k', 'H', 'o', 'u', 's', 'e', ' ', 'c', 'l', 'i', 'e', 'n', 't',
		0x15, 0x08, 0xb1, 0xa9, 0x03, 0x00, 0x07, 'd', 'e', 'f', 'a', 'u', 'l', 't', 0x00,
	}
}

func nacosRaft() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x08}
}
