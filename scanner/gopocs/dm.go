// gopocs/dm.go
package gopocs

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "gitee.com/chunanyong/dm" // 达梦数据库驱动
)

//go:embed dict/dm.txt
var dmUserPassDict string

func DmScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()

	var userPassList []struct{ User, Pass string }

	// ===== 1. 来源：全局单个密码（仅用于搭配 UserPass 中的用户）=====
	if info.Password != "" {
		for _, upStr := range info.UserPass {
			user, _ := splitUserPass(upStr)
			if user != "" {
				userPassList = append(userPassList, struct{ User, Pass string }{user, info.Password})
			}
		}
	}

	// ===== 2. 来源：密码文件（每行一个密码，搭配 info.UserPass 中的用户）=====
	if info.PasswordFile != "" {
		b, err := os.ReadFile(info.PasswordFile)
		if err == nil {
			content := strings.ReplaceAll(string(b), "\r\n", "\n")
			for _, line := range strings.Split(content, "\n") {
				pass := strings.TrimSpace(line)
				if pass != "" {
					for _, upStr := range info.UserPass {
						user, _ := splitUserPass(upStr)
						if user != "" {
							userPassList = append(userPassList, struct{ User, Pass string }{user, pass})
						}
					}
				}
			}
		}
	}

	// ===== 3. 来源：info.UserPass（格式：user:pass）=====
	for _, upStr := range info.UserPass {
		user, pass := splitUserPass(upStr)
		if user != "" || pass != "" { // 允许空用户或空密码
			userPassList = append(userPassList, struct{ User, Pass string }{user, pass})
		}
	}
	// ===== 4. 来源：内置字典 dm.txt（格式：user:pass）=====
	lines := strings.Split(strings.ReplaceAll(dmUserPassDict, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pass := splitUserPass(line)
		userPassList = append(userPassList, struct{ User, Pass string }{user, pass})
	}
	// 项目凭据只做增量补充，内置字典始终排在其前面。
	for _, pair := range info.UserPassPairs {
		userPassList = append(userPassList, struct{ User, Pass string }{pair.UserName, pair.Password})
	}

	// ===== 去重 =====
	userPassList = dedupUserPass(userPassList)

	// ===== 模板替换：{user} 和 {{key}} =====
	var expandedList []struct{ User, Pass string }
	keys := append(info.InfoStr, "dm", "admin", "password", "123", "123456", "888", "sysdba")

	for _, item := range userPassList {
		pass := item.Pass

		// 替换 {user}
		if strings.Contains(pass, "{user}") {
			pass = strings.ReplaceAll(pass, "{user}", item.User)
		}

		// 替换 {{key}}
		if strings.Contains(pass, "{{key}}") {
			for _, key := range keys {
				newPass := strings.ReplaceAll(pass, "{{key}}", key)
				expandedList = append(expandedList, struct{ User, Pass string }{item.User, newPass})
			}
		} else {
			expandedList = append(expandedList, struct{ User, Pass string }{item.User, pass})
		}
	}

	expandedList = dedupUserPass(expandedList)
	if info.CredentialPairLimit > 0 && len(expandedList) > info.CredentialPairLimit {
		expandedList = expandedList[:info.CredentialPairLimit]
	}

	// ===== 开始爆破 =====
	gologger.AuditTimeLogger("[Go] [DM-Brute] Starting brute force on %s:%s, total %d credentials", info.Host, info.Ports, len(expandedList))

	for i, cred := range expandedList {
		username := cred.User
		password := cred.Pass

		gologger.AuditTimeLogger("[Go] [DM-Brute] Trying %s:%s | User: %s | Pass: %s (%d/%d)",
			info.Host, info.Ports, username, maskPassword(password), i+1, len(expandedList))

		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		flag, err := DmConnWithContext(ctx, info, username, password)
		cancel()

		if flag && err == nil {
			gologger.AuditTimeLogger("[Go] ✅ DM 登录成功: %s:%s | %s/%s", info.Host, info.Ports, username, maskPassword(password))
			return nil
		}

		tmperr = err

		if CheckErrs(err) {
			gologger.AuditTimeLogger("[Go] [DM-Brute] Fatal error, breaking: %v", err)
			return err
		}

		if time.Now().Unix()-starttime > int64(len(expandedList))*6 {
			gologger.AuditTimeLogger("[Go] [DM-Brute] Timeout, breaking... %s:%s", info.Host, info.Ports)
			return tmperr
		}
	}

	gologger.AuditTimeLogger("[Go] [DM-Brute] 所有凭证尝试完毕，未成功登录 %s:%s", info.Host, info.Ports)
	return tmperr
}

// DmConnWithContext 使用 context 控制超时
func DmConnWithContext(ctx context.Context, info *structs.HostInfo, user, pass string) (flag bool, err error) {
	host, portStr := info.Host, info.Ports
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, fmt.Errorf("invalid port: %s", portStr)
	}

	dataSourceName := fmt.Sprintf("dm://%s:%s@%s:%d", url.QueryEscape(user), url.QueryEscape(pass), host, port)
	gologger.AuditTimeLogger("[Go] [DM-Conn] Connecting: %s:%d %s/%s", host, port, user, maskPassword(pass))

	db, err := sql.Open("dm", dataSourceName)
	if err != nil {
		return false, err
	}
	defer db.Close()

	done := make(chan error, 1)
	go func() {
		done <- db.Ping()
	}()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case err = <-done:
		if err != nil {
			return false, err
		}
	}

	// ✅ 成功
	flag = true

	passwordDisplay := pass
	if pass == "" {
		passwordDisplay = "<empty>"
	}
	result := fmt.Sprintf("DM://%s:%s | %s/%s", host, portStr, user, passwordDisplay)
	showData := fmt.Sprintf("Host: %s:%s\nUsername: %s\nPassword: %s\n", host, portStr, user, passwordDisplay)

	securityLevel := "HIGH"
	if pass != "" {
		securityLevel = "CRITICAL"
	}

	emitOutput(info, ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "DM-Login",
			Security:    securityLevel,
			Target:      host + ":" + portStr,
			InfoLeft:    showData,
			Description: "达梦数据库弱口令",
			ShowMsg:     result,
		},
	})

	writeResult(info, structs.GoPocsResultType{
		PocName:     "DM-Login",
		Security:    securityLevel,
		Target:      host + ":" + portStr,
		InfoLeft:    showData,
		Description: "达梦数据库弱口令",
	})

	return true, nil
}

// dedupUserPass 去重
func dedupUserPass(list []struct{ User, Pass string }) []struct{ User, Pass string } {
	seen := sync.Map{}
	var result []struct{ User, Pass string }
	for _, item := range list {
		key := item.User + ":" + item.Pass
		if _, loaded := seen.LoadOrStore(key, true); !loaded {
			result = append(result, item)
		}
	}
	return result
}
