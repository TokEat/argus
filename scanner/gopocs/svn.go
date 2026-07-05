package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"fmt"
	"strings"
	"time"
)

func SVNScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Read SVN banner
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "success") || !strings.Contains(resp, "SVN") {
		return nil
	}

	result := fmt.Sprintf("SVN://%s Repository Detected", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "SVN-Detect",
			Security:    "INFO",
			Target:      realhost,
			Description: "SVN仓库服务检测",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "SVN-Detect",
		Security:    "INFO",
		Target:      realhost,
		Description: "SVN仓库服务检测",
	})
	return nil
}
