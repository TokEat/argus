package gopocs

import (
	"bufio"
	"crypto/md5"
	"dddd/scanner/ddout"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"encoding/base64"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

const (
	RsyncProtocol  = "@RSYNCD: 31\n"
	rsyncIOTimeout = 10 * time.Second
)

// getUserList 返回用户名字典
func getUserList() []string {
	return []string{"root", "admin", "rsync", "user", "administrator", "backup", ""}
}

// getPassList 返回密码字典
func getPassList() []string {
	return []string{"", "123456", "12345678", "password", "admin123", "root", "toor", "test", "admin", "P@ssw0rd", "1qaz@WSX"}
}

// maskPassword keeps empty credentials readable while preserving successful brute-force evidence.
func maskPassword(p string) string {
	if p == "" {
		return "<empty>"
	}
	return p
}

// RsyncScan 主入口函数，符合 dddd gopoc 规范
func RsyncScan(info *structs.HostInfo) (err error) {
	address := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	gologger.AuditTimeLogger("[Go] [Rsync] Starting scan on %s", address)

	// 1. 获取模块列表
	modules, err := getModuleList(address)
	if err != nil {
		gologger.AuditTimeLogger("[Go] [Rsync] Failed to get module list: %v", err)
		return err
	}
	if len(modules) == 0 {
		gologger.AuditTimeLogger("[Go] [Rsync] No modules found on %s", address)
		return nil
	}

	gologger.AuditTimeLogger("[Go] [Rsync] Found %d module(s): %v", len(modules), modules)

	// 2. 遍历每个模块
	for _, module := range modules {
		gologger.AuditTimeLogger("[Go] [Rsync] Testing module: %s", module)

		// 先测试是否未授权访问（空用户空密码）
		success, msg := tryLogin(address, module, "", "")
		if success {
			gologger.AuditTimeLogger("[Go] ✅ %s", msg)

			// 输出未授权访问结果
			result := fmt.Sprintf("Rsync://%s/%s", address, module)
			showData := fmt.Sprintf("Module: %s\nUsername: <empty>\nPassword: <empty>\n", module)

			emitOutput(info, ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{
					PocName:     "Rsync-Brute",
					Security:    "HIGH",
					Target:      address,
					InfoLeft:    showData,
					InfoRight:   "Rsync 未授权访问",
					Description: "Rsync 未授权访问或弱口令",
					ShowMsg:     result,
				},
				AdditionalMsg: "",
			})

			writeResult(info, structs.GoPocsResultType{
				PocName:     "Rsync-Brute",
				Security:    "HIGH",
				Target:      address,
				InfoLeft:    showData,
				Description: "Rsync 未授权访问或弱口令",
			})

			// 加个小延迟，确保输出刷出
			time.Sleep(50 * time.Millisecond)

			return nil
		}

		// 否则爆破
		gologger.AuditTimeLogger("[Go] [Rsync] Module %s requires auth, starting brute force...", module)

		users := getUserList()
		passes := getPassList()

		// 合并自定义用户密码（如果有）
		if len(info.UserPass) > 0 {
			var customUsers, customPasses []string
			for _, up := range info.UserPass {
				user, pass := splitUserPass(up)
				if user != "" {
					customUsers = append(customUsers, user)
				}
				if pass != "" {
					customPasses = append(customPasses, pass)
				}
			}
			users = utils.RemoveDuplicateElement(append(users, customUsers...))
			passes = utils.RemoveDuplicateElement(append(passes, customPasses...))
		}

		for _, user := range users {
			for _, pass := range passes {
				maskedPass := maskPassword(pass)
				gologger.AuditTimeLogger("[Go] [Rsync] Trying %s:%s on module %s", user, maskedPass, module)

				success, msg := tryLogin(address, module, user, pass)
				if success {
					gologger.AuditTimeLogger("[Go] ✅ %s", msg)

					// 输出暴力破解成功的结果
					result := fmt.Sprintf("Rsync://%s/%s", address, module)
					showData := fmt.Sprintf("Module: %s\nUsername: %s\nPassword: %s\n", module, user, maskedPass)

					emitOutput(info, ddout.OutputMessage{
						Type:     "GoPoc",
						IP:       "",
						IPs:      nil,
						Port:     "",
						Protocol: "",
						Web:      ddout.WebInfo{},
						Finger:   nil,
						Domain:   "",
						GoPoc: ddout.GoPocsResultType{
							PocName:     "Rsync-Brute",
							Security:    "HIGH",
							Target:      address,
							InfoLeft:    showData,
							InfoRight:   fmt.Sprintf("Module: %s, Access: Authenticated", module),
							Description: "Rsync 弱口令",
							ShowMsg:     result,
						},
						AdditionalMsg: "",
					})

					writeResult(info, structs.GoPocsResultType{
						PocName:     "Rsync-Brute",
						Security:    "HIGH",
						Target:      address,
						InfoLeft:    showData,
						Description: "Rsync 弱口令",
					})

					// 加个小延迟，确保输出刷出
					time.Sleep(50 * time.Millisecond)

					return nil
				}

				time.Sleep(100 * time.Millisecond) // 避免太快
			}
		}
	}

	gologger.AuditTimeLogger("[Go] [Rsync] All modules tested, no vulnerability found on %s", address)
	return nil
}

// getModuleList 获取 rsync 模块列表
func getModuleList(address string) ([]string, error) {
	conn, err := utils.WrapperTcpWithTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rsyncIOTimeout))

	// 1. 发送协议
	_, err = conn.Write([]byte(RsyncProtocol))
	if err != nil {
		return nil, fmt.Errorf("send protocol failed: %w", err)
	}

	// 2. 读取响应
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read protocol response: %w", err)
	}
	line = strings.TrimSpace(line)

	// 3. 发送换行，获取模块列表
	if _, err = conn.Write([]byte("\n")); err != nil {
		return nil, fmt.Errorf("send newline failed: %w", err)
	}

	var modules []string
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(string(lineBytes))

		if line == "" || line == "@RSYNCD: EXIT" {
			break
		}
		if strings.HasPrefix(line, "@RSYNCD:") {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		moduleName := strings.TrimSpace(parts[0])
		if moduleName != "" {
			modules = append(modules, moduleName)
		}
	}

	return modules, nil
}

// tryLogin 尝试登录模块（支持未授权和认证）
func tryLogin(address, module, username, password string) (bool, string) {
	conn, err := utils.WrapperTcpWithTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return false, fmt.Sprintf("connect failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rsyncIOTimeout))

	reader := bufio.NewReader(conn)

	if _, err := conn.Write([]byte(RsyncProtocol)); err != nil {
		return false, fmt.Sprintf("write error: %v", err)
	}
	_, _ = reader.ReadString('\n')

	if _, err := conn.Write([]byte(module + "\n")); err != nil {
		return false, fmt.Sprintf("write error: %v", err)
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return false, "read response failed"
	}
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "@RSYNCD: OK") {
		return true, fmt.Sprintf("✅ No Auth! Module=[%s]", module)
	}

	if strings.HasPrefix(line, "@RSYNCD: AUTHREQD") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return false, "invalid authreqd format"
		}
		challenge := strings.TrimSuffix(parts[2], "\n")

		raw := password + challenge
		hash := md5.Sum([]byte(raw))
		response := base64.StdEncoding.EncodeToString(hash[:])

		authLine := fmt.Sprintf("%s %s\n", username, response)
		_, err = conn.Write([]byte(authLine))
		if err != nil {
			return false, "send auth failed"
		}

		resultLine, _ := reader.ReadString('\n')
		resultLine = strings.TrimSpace(resultLine)

		if strings.Contains(resultLine, "RSYNCD: OK") {
			return true, fmt.Sprintf("✅ Auth Success! Module=[%s] User=[%s] Pass=[%s]", module, username, maskPassword(password))
		}
		return false, "auth failed"
	}

	return false, "access denied"
}
