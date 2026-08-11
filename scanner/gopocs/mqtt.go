package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"time"
)

func MQTTScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// MQTT CONNECT with anonymous access (no username/password)
	connectPkt, _ := hex.DecodeString("101600044d5154540402003c000a61726775735f73636e")
	conn.Write(connectPkt)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	// CONNACK: 0x20 0x02 0x00 returnCode
	if buf[0] != 0x20 {
		return nil
	}
	returnCode := buf[3]
	if returnCode != 0x00 {
		return nil
	}

	result := fmt.Sprintf("MQTT://%s Anonymous Access OK", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "MQTT-Anonymous",
			Security:    "HIGH",
			Target:      realhost,
			Description: "MQTT Broker匿名访问",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "MQTT-Anonymous",
		Security:    "HIGH",
		Target:      realhost,
		Description: "MQTT Broker匿名访问",
	})
	return nil
}
