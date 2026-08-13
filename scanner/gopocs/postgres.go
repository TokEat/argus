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

//go:embed dict/postgresql.txt
var postgreSQLUserPasswdDict string

func PostgresScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	defer gologger.AuditTimeLogger("[Go] [PostgreSQL] PostgresScan return! %s:%v", info.Host, info.Ports)

	userPasswdList := sortUserPassword(info, postgreSQLUserPasswdDict, []string{"Postgres"})

	for _, userPass := range userPasswdList {
		flag, err := PostgresConn(info, userPass.UserName, userPass.Password)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no connection could be made because the target machine actively refused it") {
				continue
			}
		}

		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				return err
			}
		}
	}

	return tmperr
}

func PostgresConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	waitCredentialAttempt(info)
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", url.QueryEscape(Username), url.QueryEscape(Password), Host, Port, "postgres", "disable")
	gologger.AuditTimeLogger("[Go] [PostgreSQL-Brute] start try %s:%s %s/%s", Host, Port, maskUsername(Username), maskPassword(Password))
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(5) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("PostgreSQL://%v:%v %v %v", Host, Port, Username, Password)
			// gologger.Silent().Msg("[GoPoc] " + result)

			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)
			msg := ""
			if tables := dbTableListStr(db, "postgres"); tables != "" {
				msg = "Tables(sample): " + tables + "\n"
			}

			emitOutput(info, ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{PocName: "PostgreSQL-Login",
					Security:    "CRITICAL",
					Target:      Host + ":" + Port,
					InfoLeft:    showData,
					InfoRight:   msg,
					Description: "PostgreSQL弱口令",
					ShowMsg:     result},
				AdditionalMsg: "",
			})

			writeResult(info, structs.GoPocsResultType{
				PocName:     "PostgreSQL-Login",
				Security:    "CRITICAL",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				InfoRight:   msg,
				Description: "PostgreSQL弱口令",
			})

		}
	}
	return flag, err
}
