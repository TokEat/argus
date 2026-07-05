package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func CassandraScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// CQL OPTIONS request (v4)
	optionsReq, _ := hex.DecodeString("0400000005000000000000")
	conn.Write(optionsReq)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "CQL_VERSION") {
		return nil
	}

	result := fmt.Sprintf("CQL://%s Cassandra Unauthorized", realhost)
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Cassandra-Unauthorized",
			Security:    "HIGH",
			Target:      realhost,
			Description: "CQL数据库未授权访问",
			ShowMsg:     result,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     "Cassandra-Unauthorized",
		Security:    "HIGH",
		Target:      realhost,
		Description: "CQL数据库未授权访问",
	})
	return nil
}
