// gopocs/vnc.go
package gopocs

import (
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	_ "embed"
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/projectdiscovery/gologger"
	"os"
	"strings"
	"time"
)

//go:embed dict/vnc.txt
var vncPasswordDict string

func VncScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()

	// 1. 尝试空密码
	gologger.AuditTimeLogger("[Go] [VNC-Unauth] Try %s:%v with empty password", info.Host, info.Ports)
	flagA, errA := VncConn(info, "")
	if flagA && errA == nil {
		gologger.AuditTimeLogger("[Go] ✅ VNC 空密码登录成功: %s:%v", info.Host, info.Ports)
		return nil
	} else if errA != nil {
		gologger.AuditTimeLogger("[Go] [VNC-Unauth] 空密码失败: %v", errA)
	}

	var passwdList []string

	// 构建密码字典
	if info.Password != "" {
		passwdList = append(passwdList, info.Password)
	}
	if info.PasswordFile != "" {
		b, err := os.ReadFile(info.PasswordFile)
		if err == nil {
			content := strings.ReplaceAll(string(b), "\r\n", "\n")
			for _, line := range strings.Split(content, "\n") {
				pass := strings.TrimSpace(line)
				if pass != "" {
					passwdList = append(passwdList, pass)
				}
			}
		}
	}
	for _, up := range info.UserPass {
		_, pass := splitUserPass(up)
		if pass != "" {
			passwdList = append(passwdList, pass)
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(vncPasswordDict, "\r\n", "\n"), "\n") {
		pass := strings.TrimSpace(line)
		if pass != "" {
			passwdList = append(passwdList, pass)
		}
	}

	passwdList = utils.RemoveDuplicateElement(passwdList)

	var expandedPassList []string
	for _, oriPass := range passwdList {
		oriPass = strings.Trim(oriPass, "\r\n ")
		if strings.Contains(oriPass, "{{key}}") {
			keys := append(info.InfoStr, "vnc", "admin", "password", "123", "888")
			for _, key := range keys {
				newPass := strings.ReplaceAll(oriPass, "{{key}}", key)
				expandedPassList = append(expandedPassList, newPass)
			}
		} else {
			expandedPassList = append(expandedPassList, oriPass)
		}
	}
	expandedPassList = utils.RemoveDuplicateElement(expandedPassList)

	// 2. 开始爆破
	for i, pass := range expandedPassList {
		gologger.AuditTimeLogger("[Go] [VNC-Brute] Trying %s:%v Pass:%s (%d/%d)", info.Host, info.Ports, maskPassword(pass), i+1, len(expandedPassList))

		flag, err := VncConn(info, pass)

		if flag && err == nil {
			gologger.AuditTimeLogger("[Go] ✅ VNC 登录成功: %s:%v 密码=%s", info.Host, info.Ports, maskPassword(pass))
			return nil
		} else {
			if err != nil {
				gologger.AuditTimeLogger("[Go] [VNC-Brute] 密码 '%s' 认证失败: %v", maskPassword(pass), err)
				tmperr = err
			} else {
				gologger.AuditTimeLogger("[Go] [VNC-Brute] 密码 '%s' 认证失败 (flag=false, err=nil)", maskPassword(pass))
			}

			if CheckErrs(err) {
				gologger.AuditTimeLogger("[Go] [VNC-Brute] 致命错误，中断爆破: %v", err)
				return err
			}

			if time.Now().Unix()-starttime > int64(len(expandedPassList))*6 {
				gologger.AuditTimeLogger("[Go] [VNC-Brute] Timeout, breaking... %s:%v", info.Host, info.Ports)
				return tmperr
			}
		}
	}

	gologger.AuditTimeLogger("[Go] [VNC-Brute] 所有密码尝试完毕，未成功登录 %s:%v", info.Host, info.Ports)
	return tmperr
}

func VncConn(info *structs.HostInfo, pass string) (flag bool, err error) {
	flag = false
	hostAddr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// 1. 建立 TCP 连接
	conn, err := utils.WrapperTcpWithTimeout("tcp", hostAddr, 6*time.Second)
	if err != nil {
		gologger.AuditTimeLogger("[Go] [VNC-Conn] 连接失败: %v", err)
		return false, err
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// 2. 设置读超时
	err = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	if err != nil {
		gologger.AuditTimeLogger("[Go] [VNC-Conn] 设置超时失败: %v", err)
		return false, err
	}

	// 3. 尝试 VNC 认证（关键：移除 Exclusive=true）
	vncClient, err := vnc.Client(conn, &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{Password: pass},
		},
		// Exclusive: true,  // ❌ 注释掉！某些 VNC 服务拒绝此模式
	})

	if err != nil {
		gologger.AuditTimeLogger("[Go] [VNC-Conn] 认证失败 (vnc.Client): %v", err)
		return false, err
	}

	// 4. 成功连接
	defer vncClient.Close()
	flag = true

	// 5. 输出成功结果
	passwordDisplay := pass
	if pass == "" {
		passwordDisplay = "<empty>"
	}
	result := fmt.Sprintf("VNC://%s %s", hostAddr, passwordDisplay)
	showData := fmt.Sprintf("Host: %s\nPassword: %s\n", hostAddr, passwordDisplay)

	securityLevel := "HIGH"
	if pass != "" {
		securityLevel = "CRITICAL"
	}

	emitOutput(info, ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "VNC-Login",
			Security:    securityLevel,
			Target:      hostAddr,
			InfoLeft:    showData,
			InfoRight:   "VNC authentication succeeded.",
			Description: "VNC 未授权访问或弱口令",
			ShowMsg:     result,
		},
	})

	writeResult(info, structs.GoPocsResultType{
		PocName:     "VNC-Login",
		Security:    securityLevel,
		Target:      hostAddr,
		InfoLeft:    showData,
		Description: "VNC 未授权访问或弱口令",
	})

	return true, nil
}
