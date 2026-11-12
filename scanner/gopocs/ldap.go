package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"time"
)

func LDAPScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// LDAP Anonymous Simple Bind (version 2, empty DN, empty password)
	bindReq, _ := hex.DecodeString("300c020101600702010204008000")
	written, _ := conn.Write(bindReq)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return err
	}
	// Check for BindResponse success (resultCode == 0)
	// Response: 30 0c 02 01 01 61 07 0a 01 00 04 00 04 00
	if n >= 14 && buf[9] == 0x00 {
		exchanges := []structs.GoPocExchange{
			binaryGoPocWriteExchange("LDAP anonymous bind verification", bindReq, written, buf[:n]),
		}
		result := fmt.Sprintf("LDAP://%s Anonymous Bind OK", realhost)
		info.Emit(ddout.OutputMessage{
			Type: "GoPoc",
			GoPoc: ddout.GoPocsResultType{
				PocName:     "LDAP-Anonymous",
				Security:    "HIGH",
				Target:      realhost,
				Exchanges:   exchanges,
				Description: "LDAP匿名绑定未授权访问",
				ShowMsg:     result,
			},
		})
		writeResult(info, structs.GoPocsResultType{
			PocName:     "LDAP-Anonymous",
			Security:    "HIGH",
			Target:      realhost,
			Exchanges:   exchanges,
			Description: "LDAP匿名绑定未授权访问",
		})
	}
	return nil
}
