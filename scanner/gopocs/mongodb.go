package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

func MongodbScan(info *structs.HostInfo) error {
	_, err := MongodbUnauth(info)
	return err
}

func MongodbUnauth(info *structs.HostInfo) (flag bool, err error) {
	flag = false
	// op_msg
	packet1 := []byte{
		0x69, 0x00, 0x00, 0x00, // messageLength
		0x39, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xdd, 0x07, 0x00, 0x00, // opCode OP_MSG
		0x00, 0x00, 0x00, 0x00, // flagBits
		// sections db.adminCommand({getLog: "startupWarnings"})
		0x00, 0x54, 0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x81, 0xf8, 0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84, 0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
	}
	//op_query
	packet2 := []byte{
		0x48, 0x00, 0x00, 0x00, // messageLength
		0x02, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // fullCollectionName admin.$cmd
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// query db.adminCommand({getLog: "startupWarnings"})
		0x21, 0x00, 0x00, 0x00, 0x2, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
	}

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	checkUnAuth := func(packet []byte) ([]byte, []byte, error) {
		conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			if conn != nil {
				conn.Close()
			}
		}()
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(6) * time.Second))
		if err != nil {
			return nil, nil, err
		}
		written, err := conn.Write(packet)
		gologger.AuditTimeLogger("[Go] [Mongodb] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(packet))
		if err != nil {
			return nil, nil, err
		}
		reply := make([]byte, 1024)
		count, err := conn.Read(reply)
		if err != nil {
			return nil, nil, err
		}
		gologger.AuditTimeLogger("[Go] [Mongodb] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(reply[0:count]))
		return packet[:written], reply[:count], nil
	}

	// send OP_MSG first
	selectedLabel := "MongoDB OP_MSG unauthenticated verification"
	request, response, err := checkUnAuth(packet1)
	if err != nil {
		selectedLabel = "MongoDB OP_QUERY unauthenticated verification"
		request, response, err = checkUnAuth(packet2)
		if err != nil {
			return flag, err
		}
	}
	reply := string(response)
	if strings.Contains(reply, "totalLinesWritten") {
		flag = true

		result := fmt.Sprintf("Mongodb://%s Unauthorized", realhost)
		// gologger.Silent().Msg(result)
		exchanges := []structs.GoPocExchange{
			binaryGoPocExchange(selectedLabel, request, response),
		}
		pocResult := structs.GoPocsResultType{
			PocName:     "Mongodb-Unauthorized",
			Security:    "HIGH",
			Target:      realhost,
			InfoLeft:    reply,
			Exchanges:   exchanges,
			Description: "Mongodb未授权访问",
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
	}
	return flag, err
}
