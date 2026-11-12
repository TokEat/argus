package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"time"
)

func RMIScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// RMI protocol handshake: JRMI + StreamProtocol
	probe, _ := hex.DecodeString("4a524d4900024b")
	written, _ := conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return err
	}
	// Expected response starts with 0x4e (N) for handshake ack
	if buf[0] != 0x4e {
		return nil
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocWriteExchange("RMI registry handshake verification", probe, written, buf[:n]),
	}

	result := fmt.Sprintf("RMI://%s Registry Exposed", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "RMI-Exposed",
			Security:    "MEDIUM",
			Target:      realhost,
			Exchanges:   exchanges,
			Description: "Java RMI注册表暴露",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "RMI-Exposed",
		Security:    "MEDIUM",
		Target:      realhost,
		Exchanges:   exchanges,
		Description: "Java RMI注册表暴露",
	})
	return nil
}
