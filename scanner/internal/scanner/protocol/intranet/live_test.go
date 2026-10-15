package intranet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestLiveIntranetTCPProbes(t *testing.T) {
	type spec struct {
		name     string
		banner   []byte
		reply    []byte
		want     string
		needRead bool
	}
	specs := []spec{
		{name: "smtp", banner: []byte("220 mail.example ESMTP Postfix\r\n"), want: "smtp"},
		{name: "imap", banner: []byte("* OK IMAP4rev1 Service Ready\r\n"), want: "imap"},
		{name: "pop3", banner: []byte("+OK POP3 ready\r\n"), want: "pop3"},
		{name: "vnc", banner: []byte("RFB 003.008\n"), want: "vnc"},
		{name: "rsync", needRead: true, reply: []byte("@RSYNCD: 31.0\n"), want: "rsync"},
		{name: "svn", needRead: true, reply: []byte("( success ( 2 2 ( ) ( edit-pipeline ) ) )\n"), want: "svn"},
		{name: "hsqldb", banner: []byte("HSQLDB JDBC Network Listener.\nVersion(2.7.1)\n"), want: "hsqldb"},
		{name: "ldap", needRead: true, reply: []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, want: "ldap"},
		{name: "kerberos", needRead: true, reply: []byte{0x00, 0x00, 0x00, 0x05, 0x7e, 0x03, 0x00, 0x00, 0x00}, want: "kerberos"},
		{name: "rpc", needRead: true, reply: rpcReply(1), want: "rpc"},
		{name: "netbios", needRead: true, reply: []byte{0x82, 0x00, 0x00, 0x00}, want: "netbios"},
		{name: "dns", needRead: true, reply: dnsResponse(), want: "dns"},
		{name: "nfs", needRead: true, reply: rpcReply(0), want: "nfs"},
		{name: "postgresql", needRead: true, reply: []byte("E\x00\x00\x00\x2cSFATAL\x00C28P01\x00Mpassword\x00\x00"), want: "postgresql"},
		{name: "kingbase", needRead: true, reply: []byte("E\x00\x00\x00\x30SFATAL\x00C28P01\x00MKingbaseES auth\x00\x00"), want: "kingbase"},
		{name: "tidb", banner: tidbGreeting("5.7.25-TiDB-v7.5.0"), want: "tidb"},
		{name: "mqtt", needRead: true, reply: []byte{0x20, 0x02, 0x00, 0x00}, want: "mqtt"},
		{name: "amqp", needRead: true, reply: []byte("AMQP\x00\x00\x09\x01"), want: "amqp"},
		{name: "dubbo", needRead: true, reply: []byte("OK\r\ndubbo>\r\n"), want: "dubbo"},
		{name: "rocketmq-broker", needRead: true, reply: rocketMQTestFrameBytes(), want: "rocketmq-broker"},
		{name: "rocketmq-namesrv", needRead: true, reply: rocketMQTestFrameBytes(), want: "rocketmq-namesrv"},
		{name: "epmd", needRead: true, reply: []byte("\x00\x00\x11\x11name rabbit at port 25672\n"), want: "epmd"},
		{name: "jboss-remoting", banner: []byte("\x00\x00\x00\x3e\x00\x00\x01\x00\x03\x04\x00\x00\x00\x03\x03\x04\x00\x00\x00\x02\x01\x06GSSAPI\x01\x0aDIGEST-MD5\x01\x08CRAM-MD5\x02\x0ejboss.local"), want: "jboss-remoting"},
		{name: "weblogic-t3", needRead: true, reply: []byte("HELO:12.2.1.4.false\nAS:255\n\n"), want: "weblogic-t3"},
		{name: "weblogic-iiop", needRead: true, reply: []byte("GIOP\x01\x00\x01\x01\x00\x00\x00\x10"), want: "iiop"},
		{name: "modbus", needRead: true, reply: []byte("\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00\x00"), want: "modbus"},
		{name: "dnp3", needRead: true, reply: []byte("\x05\x64\x05\x06\x01\x00\x00\x00\x55\xc4"), want: "dnp3"},
		{name: "s7comm", needRead: true, reply: mustHex("0300001611d00000000100c0010ac1020100c2020102"), want: "s7comm"},
		{name: "enip", needRead: true, reply: mustHex("630000000000000000000000000000000000000000000000"), want: "enip"},
		{name: "atg", needRead: true, reply: []byte("\x01ATG OK\n"), want: "atg"},
		{name: "melsec", needRead: true, reply: []byte("\xd7\x00\x00\x00\x00\x00\x00\x00\x00"), want: "melsec"},
		{name: "fins", needRead: true, reply: []byte("FINS\x00\x00\x00\x00"), want: "fins"},
		{name: "crimson", needRead: true, reply: []byte("Crimson 3"), want: "crimson"},
		{name: "iec104", needRead: true, reply: []byte("\x68\x04\x0b\x00\x00\x00"), want: "iec104"},
		{name: "pcworx", needRead: true, reply: []byte("\x81\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x00\x00\x00.\x00\x00"), want: "pcworx"},
		{name: "codesys", needRead: true, reply: []byte("\x04\xef\xef\xb3\x00\x00\x00\x01\x01\x00\xc4\x01\x00\x00\x00\x00"), want: "codesys"},
		{name: "proconos", needRead: true, reply: []byte("\xcc\x01\x00\x20\x02\x92\x00V3.4 ProConOS V3.4 PLC\x00project\x00source\x00"), want: "proconos"},
		{name: "zookeeper", needRead: true, reply: []byte("Zookeeper version: 3.8.0-test\n"), want: "zookeeper"},
		{name: "nacos", needRead: true, reply: []byte("jraft nacos raft response"), want: "nacos"},
		{name: "activemq", needRead: true, reply: []byte("CONNECTED\nversion:1.2\nserver:ActiveMQ/5.18\n\n\x00"), want: "activemq"},
		{name: "msmq", needRead: true, reply: []byte("MSMQ\x00"), want: "msmq"},
		{name: "sap-p4", needRead: true, reply: []byte("NI_PONG\x00SAP"), want: "sap-p4"},
		{name: "cassandra", needRead: true, reply: cassandraOptionsSupported(), want: "cassandra"},
		{name: "clickhouse", needRead: true, reply: []byte("\x00ClickHouse 23.8.1"), want: "clickhouse"},
		{name: "dm", banner: []byte("DM Database Server 8.1\n"), want: "dm"},
	}

	for _, s := range specs {
		s := s
		t.Run(s.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go serveLive(ln, s.banner, s.reply, s.needRead, done)
			port := ln.Addr().(*net.TCPAddr).Port
			rec, ok := runNamedProbe("127.0.0.1", port, 2*time.Second, s.name)
			<-done
			if !ok || rec.Protocol != s.want {
				t.Fatalf("got %+v ok=%v want %s", rec, ok, s.want)
			}
		})
	}
}

func TestLiveProbeUnknownPortSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go serveLive(ln, []byte("220 mail.example ESMTP Postfix\r\n"), nil, false, done)
	port := ln.Addr().(*net.TCPAddr).Port
	rec, ok := Probe("127.0.0.1", port, time.Second, structs.ServiceRecord{Protocol: "tcp"})
	<-done
	if !ok || rec.Protocol != "smtp" {
		t.Fatalf("unknown-port smtp = %+v ok=%v", rec, ok)
	}
	_ = strconv.Itoa(port)
}

func serveLive(ln net.Listener, banner, reply []byte, needRead bool, done chan struct{}) {
	defer close(done)
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if len(banner) > 0 {
		_, _ = conn.Write(banner)
	}
	if needRead {
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		if len(reply) > 0 {
			_, _ = conn.Write(reply)
		}
	} else if len(reply) > 0 {
		_, _ = io.CopyN(io.Discard, conn, 0)
		_, _ = conn.Write(reply)
	}
}

func rpcReply(acceptStat byte) []byte {
	body := make([]byte, 24)
	body[0], body[1], body[2], body[3] = 0x72, 0xfe, 0x1d, 0x13
	body[7] = 1
	body[23] = acceptStat
	return append([]byte{0x80, 0x00, 0x00, 0x18}, body...)
}

func dnsResponse() []byte {
	msg := make([]byte, 12)
	msg[2] = 0x81
	msg[3] = 0x80
	return append([]byte{0x00, 0x0c}, msg...)
}

func TestLiveLDAPSWithEphemeralCert(t *testing.T) {
	cert := mustTestCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	rec, ok := runNamedProbe("127.0.0.1", port, 2*time.Second, "ldaps")
	<-done
	if !ok || rec.Protocol != "ldaps" {
		t.Fatalf("ldaps = %+v ok=%v", rec, ok)
	}
}

func mustTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "argus-ldaps-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
