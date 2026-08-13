package gopocs

import (
	_ "embed"
	"errors"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

//go:embed dict/rdp.txt
var rdpUserPasswdDict string

type Brutelist struct {
	user string
	pass string
}

func RdpScan(info *structs.HostInfo) (tmperr error) {
	return rdpScanWithConnector(info, RdpConnWithEvidence)
}

type rdpConnector func(string, string, string, string, int, int64) (bool, []structs.GoPocExchange, error)

func rdpScanWithConnector(info *structs.HostInfo, connect rdpConnector) (tmperr error) {
	userPasswdList := sortUserPassword(info, rdpUserPasswdDict, []string{})
	gologger.AuditTimeLogger("[Go] [RDP-Brute] start try %s:%v", info.Host, info.Ports)
	defer gologger.AuditTimeLogger("[Go] [RDP-Brute] RdpScan return %s:%v", info.Host, info.Ports)

	var wg sync.WaitGroup
	var signal bool
	var num = 0
	var all = len(userPasswdList)
	var mutex sync.Mutex
	var workerErr error
	brlist := make(chan Brutelist, all)
	port, _ := strconv.Atoi(info.Ports)

	for _, userPass := range userPasswdList {
		brlist <- Brutelist{userPass.UserName, userPass.Password}
	}

	for i := 0; i < 1; i++ {
		wg.Add(1)
		go worker(info, info.Host, "", port, &wg, brlist, &signal, &num, all, &mutex, &workerErr, 6, connect)
	}

	close(brlist)
	wg.Wait()

	return workerErr
}

func worker(info *structs.HostInfo, host, domain string, port int, wg *sync.WaitGroup, brlist chan Brutelist, signal *bool, num *int, all int, mutex *sync.Mutex, workerErr *error, timeout int64, connect rdpConnector) {
	defer wg.Done()
	for one := range brlist {
		mutex.Lock()
		stopped := *signal
		mutex.Unlock()
		if stopped {
			return
		}
		go incrNum(num, mutex)
		user, pass := one.user, one.pass
		gologger.AuditTimeLogger("[Go] [RDP-Brute] start try %s:%v %v %v", host, port, maskUsername(user), maskPassword(pass))

		waitCredentialAttempt(info)
		flag, exchanges, err := connect(host, domain, user, pass, port, timeout)
		if isSuccessfulSessionEvidenceError(err) {
			mutex.Lock()
			*workerErr = err
			*signal = true
			mutex.Unlock()
			return
		}
		if flag == true && err == nil {
			var result string
			if domain != "" {
				result = fmt.Sprintf("RDP://%v:%v:%v\\%v %v", host, port, domain, user, pass)
			} else {
				result = fmt.Sprintf("RDP://%v:%v:%v %v", host, port, user, pass)
			}

			// gologger.Silent().Msg("[GoPoc] " + result)
			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", host, port, user, pass)

			pocResult := structs.GoPocsResultType{
				PocName:     "RDP-Login",
				Security:    "CRITICAL",
				Target:      fmt.Sprintf("%v:%v", host, port),
				InfoLeft:    showData,
				Exchanges:   exchanges,
				Description: "RDP弱口令",
				ShowMsg:     result,
			}
			emitOutput(info, ddout.OutputMessage{Type: "GoPoc", GoPoc: pocResult})
			writeResult(info, pocResult)

			mutex.Lock()
			*signal = true
			mutex.Unlock()
			return
		}
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}

func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	flag, _, err := RdpConnWithEvidence(ip, domain, user, password, port, timeout)
	return flag, err
}

func RdpConnWithEvidence(ip, domain, user, password string, port int, timeout int64) (bool, []structs.GoPocExchange, error) {
	target := fmt.Sprintf("%s:%d", ip, port)
	g := NewClient(target, glog.NONE)
	exchanges, err := g.loginWithEvidence(domain, user, password, timeout, successfulSessionEvidenceLimit)

	if err == nil {
		return true, exchanges, nil
	}

	return false, nil, err
}

type rdpDialer func(string, string, time.Duration) (net.Conn, error)

type Client struct {
	Host string // ip:port
	dial rdpDialer
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

func NewClient(host string, logLevel glog.LEVEL) *Client {
	return newClientWithDialer(host, logLevel, utils.WrapperTcpWithTimeout)
}

func newClientWithDialer(host string, logLevel glog.LEVEL, dial rdpDialer) *Client {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Client{
		Host: host,
		dial: dial,
	}
}

func (g *Client) Login(domain, user, pwd string, timeout int64) error {
	conn, err := g.dialConn("tcp", g.Host, time.Duration(timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	return g.loginConn(conn, domain, user, pwd)
}

func (g *Client) loginWithEvidence(domain, user, pwd string, timeout int64, limit int) ([]structs.GoPocExchange, error) {
	return g.loginWithEvidenceUsing(timeout, limit, func(conn net.Conn) error {
		return g.loginConn(conn, domain, user, pwd)
	})
}

func (g *Client) loginWithEvidenceUsing(timeout int64, limit int, login func(net.Conn) error) ([]structs.GoPocExchange, error) {
	conn, err := g.dialConn("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("[dial err] %v", err)
	}
	return captureSuccessfulSessionEvidence(conn, "RDP authentication (TLS sessions are ciphertext)", limit, func(recordingConn net.Conn) error {
		return login(recordingConn)
	})
}

func (g *Client) dialConn(network, address string, timeout time.Duration) (net.Conn, error) {
	if g.dial != nil {
		return g.dial(network, address, timeout)
	}
	return utils.WrapperTcpWithTimeout(network, address, timeout)
}

func (g *Client) loginConn(conn net.Conn, domain, user, pwd string) error {
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	//g.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)
	//g.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	err := g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")
	wg := &sync.WaitGroup{}
	breakFlag := false
	wg.Add(1)

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		err = nil
		glog.Info("on success")
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
		g.pdu.Emit("done")
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
	})
	g.pdu.On("done", func() {
		if breakFlag == false {
			breakFlag = true
			wg.Done()
		}
	})
	wg.Wait()
	return err
}
