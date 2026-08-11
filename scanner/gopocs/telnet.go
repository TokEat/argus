package gopocs

import (
	_ "embed"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/gopocs/telnetlib"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

//go:embed dict/telnet.txt
var telnetUserPasswdDict string

func GetTelnetServerType(ip string, port int) int {
	gologger.AuditTimeLogger("[Go] [TelnetScan] GetTelnetServerType try %s:%v", ip, port)
	client := telnetlib.New(ip, port)
	err := client.Connect()
	if err != nil {
		return telnetlib.Closed
	}
	defer client.Close()
	return client.MakeServerType()
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
	serverType := GetTelnetServerType(info.Host, portInt)
	gologger.AuditTimeLogger("[Go] [TelnetScan] start try %s:%v Type: %v", info.Host, info.Ports, serverType)
	if serverType == telnetlib.UnauthorizedAccess {
		result := fmt.Sprintf("Telnet://%v:%v Unauthorized", info.Host, info.Ports)
		// gologger.Silent().Msg("[GoPoc] " + result)

		showData := fmt.Sprintf("Host: %v:%v\nUnauthorized\n", info.Host, info.Ports)

		info.Emit(ddout.OutputMessage{
			Type:     "GoPoc",
			IP:       "",
			IPs:      nil,
			Port:     "",
			Protocol: "",
			Web:      ddout.WebInfo{},
			Finger:   nil,
			Domain:   "",
			GoPoc: ddout.GoPocsResultType{PocName: "Telnet-Login",
				Security:    "CRITICAL",
				Target:      info.Host + ":" + info.Ports,
				InfoLeft:    showData,
				Description: "Telnet未授权/弱口令",
				ShowMsg:     result},
			AdditionalMsg: "",
		})

		writeResult(info, structs.GoPocsResultType{
			PocName:     "Telnet-Login",
			Security:    "CRITICAL",
			Target:      info.Host + ":" + info.Ports,
			InfoLeft:    showData,
			Description: "Telnet未授权/弱口令",
		})

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

	// Telnet爆破
	starttime := time.Now().Unix()
	total := len(upList)
	for i, userPasswd := range upList {
		// Update progress
		percent := float64(i+1) / float64(total) * 100
		if shouldRenderProgress(info) {
			fmt.Printf("\r\033[K[GoPoc] Telnet Cracking %s:%s Progress: %.0f%%", info.Host, info.Ports, percent)
		}

		user, oriPass := splitUserPass(userPasswd)
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
			gologger.AuditTimeLogger("[Go] [Telnet-Brute] start try %s:%v %v %v", info.Host, info.Ports, user, pass)
			err := TelnetCheck(info.Host, user, pass, portInt, serverType)
			if err == nil {
				if serverType == telnetlib.OnlyPassword {
					result := fmt.Sprintf("Telnet://%v:%v %s", info.Host, info.Ports, pass)
					// gologger.Silent().Msg("[GoPoc] " + result)

					showData := fmt.Sprintf("Host: %v:%v\nPass: %v\n", info.Host, info.Ports, pass)

					info.Emit(ddout.OutputMessage{
						Type:     "GoPoc",
						IP:       "",
						IPs:      nil,
						Port:     "",
						Protocol: "",
						Web:      ddout.WebInfo{},
						Finger:   nil,
						Domain:   "",
						GoPoc: ddout.GoPocsResultType{PocName: "Telnet-Login",
							Security:    "CRITICAL",
							Target:      info.Host + ":" + info.Ports,
							InfoLeft:    showData,
							Description: "Telnet未授权/弱口令",
							ShowMsg:     result},
						AdditionalMsg: "",
					})

					writeResult(info, structs.GoPocsResultType{
						PocName:     "Telnet-Login",
						Security:    "CRITICAL",
						Target:      info.Host + ":" + info.Ports,
						InfoLeft:    showData,
						Description: "Telnet未授权/弱口令",
					})

					return err
				} else if serverType == telnetlib.UsernameAndPassword {
					result := fmt.Sprintf("Telnet://%v:%v %s %s", info.Host, info.Ports, user, pass)
					if shouldRenderProgress(info) {
						gologger.Silent().Msg("[GoPoc] " + result)
					}

					showData := fmt.Sprintf("Host: %v:%v\nUser: %v\nPass: %v\n", info.Host, info.Ports, user, pass)

					info.Emit(ddout.OutputMessage{
						Type:     "GoPoc",
						IP:       "",
						IPs:      nil,
						Port:     "",
						Protocol: "",
						Web:      ddout.WebInfo{},
						Finger:   nil,
						Domain:   "",
						GoPoc: ddout.GoPocsResultType{PocName: "Telnet-Login",
							Security:    "CRITICAL",
							Target:      info.Host + ":" + info.Ports,
							InfoLeft:    showData,
							Description: "Telnet未授权/弱口令",
							ShowMsg:     result},
						AdditionalMsg: "",
					})

					writeResult(info, structs.GoPocsResultType{
						PocName:     "Telnet-Login",
						Security:    "CRITICAL",
						Target:      info.Host + ":" + info.Ports,
						InfoLeft:    showData,
						Description: "Telnet未授权/弱口令",
					})

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
	client := telnetlib.New(addr, port)
	err := client.Connect()
	if err != nil {
		return err
	}
	defer client.Close()
	client.UserName = username
	client.Password = password
	client.ServerType = serverType
	err = client.Login()
	if err != nil {
		return err
	}
	return nil
}
