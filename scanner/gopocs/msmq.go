package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"encoding/hex"
	"fmt"
	"time"
)

func MSMQScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// MSMQ Ping packet
	probe, _ := hex.DecodeString("10010000000000000000000000000000")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}

	result := fmt.Sprintf("MSMQ://%s Service Detected", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "MSMQ-Detect",
			Security:    "INFO",
			Target:      realhost,
			Description: "Microsoft消息队列服务",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "MSMQ-Detect",
		Security:    "INFO",
		Target:      realhost,
		Description: "Microsoft消息队列服务",
	})
	return nil
}
