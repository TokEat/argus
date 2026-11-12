package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

func JDWPScan(info *structs.HostInfo) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	handshakeRequest := []byte("JDWP-Handshake")
	idSizesRequest := []byte("\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x07")
	versionRequest := []byte("\x00\x00\x00\x0b\x00\x00\x00\x03\x00\x01\x01")
	exchanges := make([]structs.GoPocExchange, 0, 3)
	client, err := utils.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err != nil {
		return err
	}

	err = client.SetDeadline(time.Now().Add(time.Duration(6) * time.Second))
	if err != nil {
		return err
	}
	written, err := client.Write(handshakeRequest)
	gologger.AuditTimeLogger("[Go] [JDWP] [1/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(handshakeRequest))
	if err != nil {
		return err
	}

	rev := make([]byte, 1024)
	n, errRead := client.Read(rev)
	if errRead != nil {
		return errRead
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [1/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	if !strings.Contains(string(rev[:n]), "JDWP-Handshake") {
		// 不是JDWP
		return err
	}
	exchanges = append(exchanges, binaryGoPocExchange("JDWP handshake", handshakeRequest[:written], rev[:n]))

	written, err = client.Write(idSizesRequest)
	gologger.AuditTimeLogger("[Go] [JDWP] [2/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(idSizesRequest))
	if err != nil {
		return err
	}

	rev = make([]byte, 1024)
	n, errRead = client.Read(rev)
	if errRead != nil {
		return errRead
	}
	if n == 0 {
		return err
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [2/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	exchanges = append(exchanges, binaryGoPocExchange("JDWP VirtualMachine.IDSizes", idSizesRequest[:written], rev[:n]))
	written, err = client.Write(versionRequest)
	gologger.AuditTimeLogger("[Go] [JDWP] [3/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(versionRequest))
	if err != nil {
		return err
	}

	rev = make([]byte, 1024)
	n, errRead = client.Read(rev)
	if errRead != nil {
		return errRead
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [3/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	data := string(rev[:n])
	if !strings.Contains(data, "Java Debug Wire Protocol") {
		return err
	}
	exchanges = append(exchanges, binaryGoPocExchange("JDWP VirtualMachine.Version", versionRequest[:written], rev[:n]))

	javaInfo := data[15:]
	result := fmt.Sprintf("JDWP://%s Unauthorized", realhost)
	// gologger.Silent().Msg(result)
	pocResult := structs.GoPocsResultType{
		PocName:     "JDWP-Unauthorized",
		Security:    "CRITICAL",
		Target:      realhost,
		InfoLeft:    javaInfo,
		Exchanges:   exchanges,
		Description: "JDWP未授权访问,可尝试RCE",
		ShowMsg:     result,
	}

	info.Emit(ddout.OutputMessage{
		Type:          "GoPoc",
		IP:            "",
		IPs:           nil,
		Port:          "",
		Protocol:      "",
		Web:           ddout.WebInfo{},
		Finger:        nil,
		Domain:        "",
		GoPoc:         pocResult,
		AdditionalMsg: "",
	})

	writeResult(info, pocResult)

	return err
}
