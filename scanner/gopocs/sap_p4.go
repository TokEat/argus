package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"fmt"
	"strings"
	"time"
)

func SAPP4Scan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// SAP P4 (NI protocol) route string ping
	probe := []byte("NI_PING\x00")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "NI") && !strings.Contains(resp, "SAP") {
		return nil
	}

	result := fmt.Sprintf("SAP-P4://%s NetWeaver Detected", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "SAP-P4-Detect",
			Security:    "MEDIUM",
			Target:      realhost,
			Description: "SAP NetWeaver Java P4协议检测",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "SAP-P4-Detect",
		Security:    "MEDIUM",
		Target:      realhost,
		Description: "SAP NetWeaver Java P4协议检测",
	})
	return nil
}
