// Package protocolwire contains small, side-effect-free validators for binary
// protocol frames shared by discovery and GoPoc checks.
package protocolwire

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// IsIEC104Frame validates the APDU envelope and control field of an
// IEC-60870-5-104 frame. The U-frame controls are the most useful response
// signatures for a read-only STARTDT probe; S and I frames are accepted when
// their length and control format are structurally valid.
func IsIEC104Frame(raw []byte) bool {
	if len(raw) < 6 || raw[0] != 0x68 {
		return false
	}
	frameLength := int(raw[1])
	if frameLength < 4 || frameLength > 253 || len(raw) < frameLength+2 {
		return false
	}

	control := raw[2]
	if control&0x03 == 0x03 {
		// U-format: the remaining three control octets are zero and the
		// first octet is one of the standardized IEC-104 U commands.
		if raw[3] != 0 || raw[4] != 0 || raw[5] != 0 {
			return false
		}
		switch control {
		case 0x07, 0x0b, 0x13, 0x23, 0x43, 0x83:
			return true
		default:
			return false
		}
	}
	if control&0x01 == 0x01 {
		// S-format has no ASDU and therefore has the minimum APDU length.
		return frameLength == 4
	}
	// I-format carries an ASDU after the four control octets.
	return frameLength >= 6
}

// MySQLServerVersion extracts the NUL-terminated server-version field from a
// MySQL protocol-10 greeting. It deliberately validates the packet envelope
// instead of searching arbitrary bytes for a product name.
func MySQLServerVersion(raw []byte) (string, bool) {
	if len(raw) < 7 || raw[3] != 0x00 || raw[4] != 0x0a {
		return "", false
	}
	payloadLength := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
	if payloadLength < 3 || payloadLength+4 > len(raw) {
		return "", false
	}
	payload := raw[5 : payloadLength+4]
	end := bytes.IndexByte(payload, 0)
	if end < 3 {
		return "", false
	}
	return string(payload[:end]), true
}

// TiDBServerVersion validates a MySQL greeting and confirms that its server
// version identifies TiDB. The returned value is the actual greeting version.
func TiDBServerVersion(raw []byte) (string, bool) {
	version, ok := MySQLServerVersion(raw)
	if !ok || !strings.Contains(strings.ToLower(version), "tidb") {
		return "", false
	}
	return version, true
}

// IsCassandraOptionsResponse validates a Cassandra native-protocol response
// to an OPTIONS request. Cassandra responses use the direction bit in the
// version octet and opcode 0x06 for SUPPORTED; the body must advertise the
// native protocol options rather than merely containing the text CQL_VERSION.
func IsCassandraOptionsResponse(raw []byte) bool {
	if len(raw) < 9 || raw[0]&0x80 == 0 {
		return false
	}
	version := raw[0] & 0x7f
	if version < 3 || version > 6 || raw[4] != 0x06 {
		return false
	}
	bodyLength := int(binary.BigEndian.Uint32(raw[5:9]))
	if bodyLength < 1 || bodyLength > len(raw)-9 {
		return false
	}
	body := raw[9 : 9+bodyLength]
	return bytes.Contains(body, []byte("CQL_VERSION")) && bytes.Contains(body, []byte("PROTOCOL_VERSIONS"))
}

// ActiveMQOpenWireVersion validates an ActiveMQ OpenWire WireFormatInfo frame
// and extracts ProviderVersion when it is present. OpenWire is length-prefixed
// and begins with command type 0x01 followed by the ActiveMQ magic; a plain
// text banner containing "ActiveMQ" is not sufficient.
func ActiveMQOpenWireVersion(raw []byte) (string, bool) {
	if len(raw) < 14 || string(raw[5:13]) != "ActiveMQ" || raw[4] != 0x01 {
		return "", false
	}
	frameLength := int(binary.BigEndian.Uint32(raw[:4]))
	if frameLength < 9 || frameLength > len(raw)-4 {
		return "", false
	}
	body := raw[4 : frameLength+4]
	if !bytes.Contains(body, []byte("ProviderName")) {
		return "", false
	}

	version := openWireStringField(body, "ProviderVersion")
	return version, true
}

func openWireStringField(body []byte, field string) string {
	index := bytes.Index(body, []byte(field))
	if index < 0 {
		return ""
	}
	rest := body[index+len(field):]
	// OpenWire's String type is followed by a two-byte length and UTF-8
	// content. ProviderVersion is encoded this way in ActiveMQ 5.x.
	for i := 0; i+3 <= len(rest); i++ {
		if rest[i] != 0x09 {
			continue
		}
		length := int(binary.BigEndian.Uint16(rest[i+1 : i+3]))
		if length == 0 || i+3+length > len(rest) {
			continue
		}
		value := rest[i+3 : i+3+length]
		if printable(value) {
			return string(value)
		}
	}
	return ""
}

func printable(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// IsZooKeeperText accepts only responses characteristic of the ZooKeeper
// four-letter command interface, including the explicit whitelist denial that
// recent ZooKeeper images return when a command is disabled.
func IsZooKeeperText(raw []byte) bool {
	trimmed := strings.TrimSpace(strings.ToLower(string(raw)))
	return trimmed == "imok" ||
		strings.Contains(trimmed, "zookeeper version:") ||
		strings.Contains(trimmed, "zk_version") ||
		strings.Contains(trimmed, "is not executed because it is not in the whitelist")
}

// ZooKeeperVersion extracts the version from a standard srvr/envi response.
func ZooKeeperVersion(raw []byte) string {
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		const prefix = "zookeeper version:"
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}
