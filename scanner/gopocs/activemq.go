package gopocs

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func ActiveMQScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Read OpenWire banner
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "ActiveMQ") {
		return nil
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocExchange("ActiveMQ OpenWire banner response", nil, buf[:n]),
	}

	version := ""
	idx := strings.Index(resp, "ProviderVersion")
	if idx > 0 {
		sub := resp[idx:]
		parts := strings.SplitN(sub, "\x09", 2)
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
			if end := strings.IndexByte(version, 0); end > 0 {
				version = version[:end]
			}
		}
	}

	result := fmt.Sprintf("ActiveMQ://%s OpenWire (version: %s)", realhost, version)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "ActiveMQ-OpenWire",
			Security:    "MEDIUM",
			Target:      realhost,
			InfoLeft:    version,
			Exchanges:   exchanges,
			Description: "ActiveMQ OpenWire协议检测 (CVE-2023-46604)",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "ActiveMQ-OpenWire",
		Security:    "MEDIUM",
		Target:      realhost,
		InfoLeft:    version,
		Exchanges:   exchanges,
		Description: "ActiveMQ OpenWire协议检测 (CVE-2023-46604)",
	})
	return nil
}
