package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"encoding/hex"
	"fmt"
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
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return err
	}
	// Expected response starts with 0x4e (N) for handshake ack
	if buf[0] != 0x4e {
		return nil
	}

	result := fmt.Sprintf("RMI://%s Registry Exposed", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "RMI-Exposed",
			Security:    "MEDIUM",
			Target:      realhost,
			Description: "Java RMI注册表暴露",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "RMI-Exposed",
		Security:    "MEDIUM",
		Target:      realhost,
		Description: "Java RMI注册表暴露",
	})
	return nil
}
