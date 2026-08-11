package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

func MemcachedScan(info *structs.HostInfo) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	request := []byte("stats\n")
	client, err := utils.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(6) * time.Second))
		if err == nil {
			var written int
			written, err = client.Write(request) //Set the key randomly to prevent the key on the server from being overwritten
			gologger.AuditTimeLogger("[Go] [Memcached] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(request))
			if err == nil {
				rev := make([]byte, 1024)
				n, errRead := client.Read(rev)
				if errRead == nil {
					gologger.AuditTimeLogger("[Go] [Memcached] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
					if strings.Contains(string(rev[:n]), "STAT") {
						result := fmt.Sprintf("Memcached://%s Unauthorized", realhost)
						// gologger.Silent().Msg(result)
						exchanges := []structs.GoPocExchange{
							binaryGoPocExchange("Memcached stats verification", request[:written], rev[:n]),
						}
						pocResult := structs.GoPocsResultType{
							PocName:     "Memcached-Unauthorized",
							Security:    "HIGH",
							Target:      realhost,
							InfoLeft:    string(rev[:n]),
							Exchanges:   exchanges,
							Description: "Memcached未授权访问",
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
				}
			}
		}
	}
	return err
}
