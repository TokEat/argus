package gopocs

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func HsqlDbScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Read banner
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "HSQLDB") {
		return nil
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocExchange("HSQLDB banner response", nil, buf[:n]),
	}

	version := ""
	if idx := strings.Index(resp, "Version("); idx > 0 {
		sub := resp[idx+8:]
		if end := strings.Index(sub, ")"); end > 0 {
			version = sub[:end]
		}
	}

	result := fmt.Sprintf("HsqlDb://%s Detected (version: %s)", realhost, version)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "HsqlDb-Detect",
			Security:    "MEDIUM",
			Target:      realhost,
			InfoLeft:    version,
			Exchanges:   exchanges,
			Description: "HsqlDb数据库检测",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "HsqlDb-Detect",
		Security:    "MEDIUM",
		Target:      realhost,
		InfoLeft:    version,
		Exchanges:   exchanges,
		Description: "HsqlDb数据库检测",
	})
	return nil
}
