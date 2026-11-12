package gopocs

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/hirochachacha/go-smb2"
	"github.com/projectdiscovery/gologger"
	"net"
	"time"
)

//go:embed dict/smb.txt
var smbUserPasswdDict string

func SmbScan(info *structs.HostInfo) (tmperr error) {
	return smbScanWithConnector(info, doWithTimeOut)
}

type smbConnector func(*structs.HostInfo, string, string) (bool, error)

func smbScanWithConnector(info *structs.HostInfo, connect smbConnector) (tmperr error) {
	starttime := time.Now().Unix()
	gologger.AuditTimeLogger("[Go] [SMB-Brute] start try %s:%v", info.Host, info.Ports)
	defer gologger.AuditTimeLogger("[Go] [SMB-Brute] SmbScan return %s:%v", info.Host, info.Ports)

	userPasswdList := sortUserPassword(info, smbUserPasswdDict, []string{})

	for _, userPass := range userPasswdList {
		gologger.AuditTimeLogger("[Go] [SMB-Brute] start try %s %v %v", info.Host, maskUsername(userPass.UserName), maskPassword(userPass.Password))
		waitCredentialAttempt(info)
		flag, err := connect(info, userPass.UserName, userPass.Password)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if isSuccessfulSessionEvidenceError(err) {
				return err
			}
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

func SmblConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	conn, err := net.Dial("tcp", info.Host+":"+info.Ports)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return smblConnWithEvidence(info, user, pass, conn, successfulSessionEvidenceLimit, authenticateSMB)
}

type smbAuthenticator func(net.Conn, string, string) ([]string, error)

func authenticateSMB(conn net.Conn, user, pass string) ([]string, error) {
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		// Share enumeration is supplemental; authentication success is the
		// vulnerability condition and remains authoritative.
		return nil, nil
	}
	return names, nil
}

func smblConnWithEvidence(info *structs.HostInfo, user, pass string, conn net.Conn, limit int, authenticate smbAuthenticator) (bool, error) {
	var names []string
	exchanges, err := captureSuccessfulSessionEvidence(conn, "SMB authentication", limit, func(recordingConn net.Conn) error {
		var authenticateErr error
		names, authenticateErr = authenticate(recordingConn, user, pass)
		return authenticateErr
	})
	if err != nil {
		return false, err
	}

	showShare := ""
	for _, name := range names {
		showShare += name + "\n"
	}

	var result string
	result = fmt.Sprintf("SMB://%v:%v:%v %v", info.Host, info.Ports, user, pass)
	// gologger.Silent().Msg(result)
	showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", info.Host, info.Ports, user, pass)

	pocResult := structs.GoPocsResultType{
		PocName:     "SMB-Login",
		Security:    "CRITICAL",
		Target:      info.Host + ":" + info.Ports,
		InfoLeft:    showData,
		InfoRight:   showShare,
		Exchanges:   exchanges,
		Description: "SMB弱口令",
		ShowMsg:     result,
	}
	emitOutput(info, ddout.OutputMessage{Type: "GoPoc", GoPoc: pocResult})
	writeResult(info, pocResult)

	return true, nil
}

type resType struct {
	err  error
	flag bool
}

func doWithTimeOut(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(7)*time.Second)
	defer cancel()

	c := make(chan resType, 1)

	go func() {

		flag, err = SmblConn(info, user, pass)
		c <- resType{
			err:  err,
			flag: flag,
		}
	}()
	select {
	case <-ctx.Done():
		res := <-c
		return false, res.err
	case res := <-c:
		return res.flag, res.err
	}
}
