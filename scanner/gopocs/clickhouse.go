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

func ClickHouseScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// ClickHouse native client hello with "default" user
	hello, _ := hex.DecodeString("0011436c69636b486f75736520636c69656e741508b1a903000764656661756c7400")
	written, _ := conn.Write(hello)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "ClickHouse") {
		return nil
	}
	exchanges := []structs.GoPocExchange{
		binaryGoPocWriteExchange("ClickHouse native hello verification", hello, written, buf[:n]),
	}

	result := fmt.Sprintf("ClickHouse://%s Native Unauthorized", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "ClickHouse-Unauthorized",
			Security:    "HIGH",
			Target:      realhost,
			Exchanges:   exchanges,
			Description: "ClickHouse数据库未授权访问",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "ClickHouse-Unauthorized",
		Security:    "HIGH",
		Target:      realhost,
		Exchanges:   exchanges,
		Description: "ClickHouse数据库未授权访问",
	})
	return nil
}
