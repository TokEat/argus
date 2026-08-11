package gopocs

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"strings"
	"time"
)

func ZookeeperScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	probe := []byte("envi\r\n")
	written, _ := conn.Write(probe)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "zookeeper.version") {
		return nil
	}

	version := ""
	for _, line := range strings.Split(resp, "\n") {
		if strings.HasPrefix(line, "zookeeper.version=") {
			version = strings.TrimPrefix(line, "zookeeper.version=")
			version = strings.TrimSpace(version)
			break
		}
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocWriteExchange("ZooKeeper envi verification", probe, written, buf[:n]),
	}

	result := fmt.Sprintf("Zookeeper://%s Unauthorized (version: %s)", realhost, version)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Zookeeper-Unauthorized",
			Security:    "HIGH",
			Target:      realhost,
			InfoLeft:    version,
			Exchanges:   exchanges,
			Description: "Zookeeper未授权访问",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "Zookeeper-Unauthorized",
		Security:    "HIGH",
		Target:      realhost,
		InfoLeft:    version,
		Exchanges:   exchanges,
		Description: "Zookeeper未授权访问",
	})
	return nil
}
