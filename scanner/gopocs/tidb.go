package gopocs

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func TiDBScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Read MySQL greeting
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "TiDB") {
		return nil
	}

	result := fmt.Sprintf("TiDB://%s MySQL Protocol Detected", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "TiDB-Detect",
			Security:    "MEDIUM",
			Target:      realhost,
			Description: "TiDB数据库未授权访问",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "TiDB-Detect",
		Security:    "MEDIUM",
		Target:      realhost,
		Description: "TiDB数据库未授权访问",
	})
	return nil
}
