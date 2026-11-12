package gopocs

import (
	"fmt"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/internal/protocolwire"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
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
	if !protocolwire.IsZooKeeperText(buf[:n]) {
		return nil
	}
	version := protocolwire.ZooKeeperVersion(buf[:n])
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
