package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func TelnetCVEScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Read telnet negotiation
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return err
	}

	hexResp := hex.EncodeToString(buf[:n])
	// CVE-2024-24061: presence of fffd24 indicates vulnerable inetutils telnet
	if !strings.Contains(hexResp, "fffd24") {
		return nil
	}

	result := fmt.Sprintf("Telnet://%s GNU inetutils (CVE-2024-24061 possible)", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Telnet-CVE-2024-24061",
			Security:    "HIGH",
			Target:      realhost,
			Description: "GNU inetutils telnet可能存在CVE-2024-24061漏洞",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "Telnet-CVE-2024-24061",
		Security:    "HIGH",
		Target:      realhost,
		Description: "GNU inetutils telnet可能存在CVE-2024-24061漏洞",
	})
	return nil
}
