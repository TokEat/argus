package gopocs

import (
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/gopocs/telnetlib"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
)

//go:embed dict/telnet.txt
var telnetUserPasswdDict string

func GetTelnetServerType(ip string, port int) int {
	serverType, _ := getTelnetServerTypeWithEvidence(ip, port)
	return serverType
}

func getTelnetServerTypeWithEvidence(ip string, port int) (int, []telnetlib.RawExchange) {
	gologger.AuditTimeLogger("[Go] [TelnetScan] GetTelnetServerType try %s:%v", ip, port)
	client := telnetlib.New(ip, port)
	err := client.Connect()
	if err != nil {
		return telnetlib.Closed, nil
	}
	defer client.Close()
	serverType := client.MakeServerType()
	if serverType != telnetlib.UnauthorizedAccess {
		return serverType, nil
	}
	return serverType, client.RawExchanges()
}

func TelnetScan(info *structs.HostInfo) (tmperr error) {
	portInt, portErr := strconv.Atoi(info.Ports)
	if portErr != nil {
		return portErr
	}

	defer func() {
		if shouldRenderProgress(info) {
			fmt.Printf("\r\033[K") // Clear progress line
		}
	}()
	defer gologger.AuditTimeLogger("[Go] [TelnetScan] TelnetScan return %s:%v", info.Host, info.Ports)

	// Telnet 未授权检测
	serverType, unauthorizedEvidence := getTelnetServerTypeWithEvidence(info.Host, portInt)
	gologger.AuditTimeLogger("[Go] [TelnetScan] start try %s:%v Type: %v", info.Host, info.Ports, serverType)
	if serverType == telnetlib.UnauthorizedAccess {
		result := fmt.Sprintf("Telnet://%v:%v Unauthorized", info.Host, info.Ports)
		// gologger.Silent().Msg("[GoPoc] " + result)

		showData := fmt.Sprintf("Host: %v:%v\nUnauthorized\n", info.Host, info.Ports)

		publishTelnetFinding(info, showData, result, unauthorizedEvidence)

		return tmperr
	}
	var upList []string
	if info.Password != "" {
		upList = append(upList, info.Password)
	} else if info.PasswordFile != "" {
		b, err := os.ReadFile(info.PasswordFile)
		if err == nil {
			t := strings.ReplaceAll(string(b), "\r\n", "\n")
			for _, v := range strings.Split(t, "\n") {
				if !strings.Contains(v, " : ") {
					continue
				}
				upList = append(upList, v)
			}
		}
	} else {
		upList = info.UserPass
		for _, v := range strings.Split(strings.ReplaceAll(telnetUserPasswdDict, "\r\n", "\n"), "\n") {
			upList = append(upList, v)
		}
	}

	upList = utils.RemoveDuplicateElement(upList)
	var credentialList []structs.UserPasswd
	for _, raw := range upList {
		user, password := splitUserPass(raw)
		credentialList = append(credentialList, structs.UserPasswd{UserName: user, Password: password})
	}
	credentialList = append(credentialList, info.UserPassPairs...)
	credentialList = limitUserPasswd(info, RemoveDuplicateUserPass(credentialList))

	// Telnet爆破
	starttime := time.Now().Unix()
	total := len(credentialList)
	for i, credential := range credentialList {
		// Update progress
		percent := float64(i+1) / float64(total) * 100
		if shouldRenderProgress(info) {
			fmt.Printf("\r\033[K[GoPoc] Telnet Cracking %s:%s Progress: %.0f%%", info.Host, info.Ports, percent)
		}

		user, oriPass := credential.UserName, credential.Password
		var passList []string
		if strings.Contains(oriPass, "{{key}}") {
			for _, sKey := range info.InfoStr {
				newPass := strings.Replace(oriPass, "{{key}}", sKey, -1)
				passList = append(passList, newPass)
			}
		} else {
			passList = append(passList, oriPass)
		}

		for _, pass := range passList {
			gologger.AuditTimeLogger("[Go] [Telnet-Brute] start try %s:%v %v %v", info.Host, info.Ports, user, maskPassword(pass))
			err, successfulEvidence := telnetCheckWithEvidence(info.Host, user, pass, portInt, serverType)
			if err == nil {
				if serverType == telnetlib.OnlyPassword {
					result := fmt.Sprintf("Telnet://%v:%v %s", info.Host, info.Ports, pass)
					// gologger.Silent().Msg("[GoPoc] " + result)

					showData := fmt.Sprintf("Host: %v:%v\nPass: %v\n", info.Host, info.Ports, pass)

					publishTelnetFinding(info, showData, result, successfulEvidence)

					return err
				} else if serverType == telnetlib.UsernameAndPassword {
					result := fmt.Sprintf("Telnet://%v:%v %s %s", info.Host, info.Ports, user, pass)
					if shouldRenderProgress(info) {
						gologger.Silent().Msg("[GoPoc] " + result)
					}

					showData := fmt.Sprintf("Host: %v:%v\nUser: %v\nPass: %v\n", info.Host, info.Ports, user, pass)

					publishTelnetFinding(info, showData, result, successfulEvidence)

					return err
				}

			}
			errStr := fmt.Sprintf("%v", err)
			if err != nil && !strings.Contains(strings.ToLower(errStr), "login failed") {
				return err
			}

			if time.Now().Unix()-starttime > (int64(len(strings.Split(telnetUserPasswdDict, "\n"))) * 6) {
				return err
			}
		}

	}

	return tmperr
}

func TelnetCheck(addr, username, password string, port, serverType int) error {
	err, _ := telnetCheckWithEvidence(addr, username, password, port, serverType)
	return err
}

func telnetCheckWithEvidence(addr, username, password string, port, serverType int) (error, []telnetlib.RawExchange) {
	client := telnetlib.New(addr, port)
	err := client.Connect()
	if err != nil {
		return err, nil
	}
	defer client.Close()
	client.UserName = username
	client.Password = password
	client.ServerType = serverType
	err = client.Login()
	if err != nil {
		return err, nil
	}
	return nil, client.RawExchanges()
}

func publishTelnetFinding(info *structs.HostInfo, showData, showMessage string, raw []telnetlib.RawExchange) {
	pocResult := structs.GoPocsResultType{
		PocName:     "Telnet-Login",
		Security:    "CRITICAL",
		Target:      info.Host + ":" + info.Ports,
		InfoLeft:    showData,
		Exchanges:   telnetGoPocExchanges(raw),
		Description: "Telnet未授权/弱口令",
		ShowMsg:     showMessage,
	}
	emitOutput(info, ddout.OutputMessage{
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

func telnetGoPocExchanges(raw []telnetlib.RawExchange) []structs.GoPocExchange {
	exchanges := make([]structs.GoPocExchange, 0, len(raw))
	for index, exchange := range raw {
		direction := "read"
		if len(exchange.Request) > 0 {
			direction = "write"
		}
		exchanges = append(exchanges, binaryGoPocExchange(
			fmt.Sprintf("Telnet I/O event %d (%s)", index+1, direction),
			exchange.Request,
			exchange.Response,
		))
	}
	return exchanges
}
