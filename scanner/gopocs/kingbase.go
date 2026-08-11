package gopocs

import (
	"database/sql"
	_ "embed"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	_ "github.com/lib/pq"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
	"time"
)

//go:embed dict/kingbase.txt
var kingbaseUserPasswdDict string

// KingbaseScan 主入口：尝试爆破 Kingbase
func KingbaseScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	defer gologger.AuditTimeLogger("[Go] [Kingbase] KingbaseScan finished! %s:%v", info.Host, info.Ports)

	// 使用统一的 sortUserPassword 函数来处理字典和用户名/密码组合
	userPasswdList := sortUserPassword(info, kingbaseUserPasswdDict, []string{"kingbase", "admin", "system"})

	for _, cred := range userPasswdList {
		// ✅ 直接使用 cred.UserName 和 cred.Password
		// ✅ 不要再做 {user} 替换，因为 sortUserPassword 已经处理了
		success, err := KingbaseConn(info, cred.UserName, cred.Password)
		if success {
			return nil
		}

		tmperr = err
		if err == nil {
			continue
		}

		// 跳过网络错误
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "connection refused") ||
			strings.Contains(errMsg, "no route to host") ||
			strings.Contains(errMsg, "connectex") {
			continue
		}

		// 检查是否是终止类错误
		if CheckErrs(err) {
			continue
		}

		// 超时控制
		if time.Now().Unix()-starttime > int64(len(userPasswdList))*6 {
			gologger.AuditTimeLogger("[Go] [Kingbase] Timeout,break! %s:%v", info.Host, info.Ports)
			return err
		}
	}

	return tmperr
}

// KingbaseConn 尝试连接 Kingbase 并返回是否成功
func KingbaseConn(info *structs.HostInfo, user, pass string) (success bool, err error) {
	rawUser := user
	rawPass := pass

	dataSourceName := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/kingbase?sslmode=disable&connect_timeout=6",
		url.QueryEscape(user), url.QueryEscape(pass), info.Host, info.Ports,
	)

	gologger.AuditTimeLogger("[Go] [Kingbase-Brute] Trying: %s:%s %s/%s", info.Host, info.Ports, rawUser, maskPassword(rawPass))

	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return false, err
	}
	defer db.Close()

	db.SetConnMaxLifetime(5 * time.Second)
	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		return false, err
	}

	// 登录成功，输出结果
	result := fmt.Sprintf("Kingbase://%s:%s %s/%s", info.Host, info.Ports, rawUser, rawPass)
	showData := fmt.Sprintf("Host: %s:%s\nUsername: %s\nPassword: %s\n", info.Host, info.Ports, rawUser, rawPass)

	emitOutput(info, ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Kingbase-Login",
			Security:    "CRITICAL",
			Target:      fmt.Sprintf("%s:%s", info.Host, info.Ports),
			InfoLeft:    showData,
			Description: "Kingbase弱口令",
			ShowMsg:     result,
		},
	})

	writeResult(info, structs.GoPocsResultType{
		PocName:     "Kingbase-Login",
		Security:    "CRITICAL",
		Target:      fmt.Sprintf("%s:%s", info.Host, info.Ports),
		InfoLeft:    showData,
		Description: "Kingbase弱口令",
	})

	return true, nil
}
