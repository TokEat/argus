package gopocs

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func NacosRaftScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Nacos JRaft protocol probe
	probe := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x08")
	written, _ := conn.Write(probe)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "nacos") && !strings.Contains(resp, "raft") && n < 10 {
		return nil
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocWriteExchange("Nacos JRaft protocol verification", probe, written, buf[:n]),
	}

	result := fmt.Sprintf("Nacos-Raft://%s JRaft Server Detected", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Nacos-Raft-Detect",
			Security:    "HIGH",
			Target:      realhost,
			Exchanges:   exchanges,
			Description: "Nacos Raft协议检测(可能存在反序列化RCE)",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "Nacos-Raft-Detect",
		Security:    "HIGH",
		Target:      realhost,
		Exchanges:   exchanges,
		Description: "Nacos Raft协议检测(可能存在反序列化RCE)",
	})
	return nil
}
