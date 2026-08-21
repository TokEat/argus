package intranet

import (
	"encoding/binary"
	"testing"
)

func TestFromBannerIntranetTCP(t *testing.T) {
	cases := []struct {
		raw  string
		port int
		want string
	}{
		{"AUTH\x01\x00\x00\x00\x00\x00\x00\x00\xbc\xb1\xa7\xb1", 25555, "adb"},
		{"\x4e\x00\x09" + "127.0.0.1" + "\x00\x00\x00\x00", 21099, "rmi"},
		{"\x00\x00\x00\x04\x00\x00\x00\x00\x00", 25051, "http2"},
		{string(tidbGreeting("5.7.25-TiDB-v7.5.0")), 4000, "tidb"},
		{"RFB 003.008\n", 5900, "vnc"},
		{"@RSYNCD: 31.0\n", 873, "rsync"},
		{"* OK IMAP4rev1 ready\r\n", 143, "imap"},
		{"+OK POP3 server ready\r\n", 110, "pop3"},
		{"220 mail.example ESMTP Postfix\r\n", 25, "smtp"},
		{"( success ( 2 2 ( ) ( edit-pipeline ) ) )\n", 3690, "svn"},
		{"HSQLDB JDBC Network Listener.\nUse JDBC driver with Network Compatibility Version2.3\n", 9001, "hsqldb"},
		{"AMQP\x00\x00\x09\x01", 5672, "amqp"},
		{"OK\r\ndubbo>\r\n", 20880, "dubbo"},
		{string(rocketMQTestFrameBytes()), 10911, "rocketmq-broker"},
		{string(rocketMQTestFrameBytes()), 9876, "rocketmq-namesrv"},
		{"\x00\x00\x11\x11name rabbit at port 25672\n", 4369, "epmd"},
		{"\x00\x00\x00\x3e\x00\x00\x01\x00\x03\x04\x00\x00\x00\x03\x03\x04\x00\x00\x00\x02\x01\x06GSSAPI\x01\x0aDIGEST-MD5\x01\x08CRAM-MD5\x02\x0ejboss.local", 4447, "jboss-remoting"},
		{"HELO:12.2.1.4.false\nAS:255\n\n", 7001, "weblogic-t3"},
		{"GIOP\x01\x00\x01\x01\x00\x00\x00\x10", 7001, "iiop"},
		{"\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00\x00", 502, "modbus"},
		{"\x05\x64\x05\x06\x01\x00\x00\x00\x55\xc4", 20000, "dnp3"},
		{"\x03\x00\x00\x16\x11\xd0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02", 102, "s7comm"},
		{string([]byte{0x63, 0x00, 0x00, 0x00}), 44818, "enip"},
		{"\x01OK\n", 10001, "atg"},
		{"\xd7\x00\x00\x00", 5006, "melsec"},
		{"FINS\x00\x00\x00\x00", 9600, "fins"},
		{"\x01\x02\x03", 789, "crimson"},
		{"\x68\x04\x0b\x00\x00\x00", 2404, "iec104"},
		{"\x81\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x00\x00\x00.\x00\x00", 1962, "pcworx"},
		{"\x04\xef\xef\xb3\x00\x00\x00\x01\x01\x00\xc4\x01\x00\x00\x00\x00", 11740, "codesys"},
		{"\xcc\x01\x00\x20\x02\x92\x00V3.4 ProConOS V3.4 PLC\x00project\x00source\x00", 20547, "proconos"},
		{"\x20\x02\x00\x00", 1883, "mqtt"},
		{"imok", 2181, "zookeeper"},
		{"Zookeeper version: 3.8.0", 2181, "zookeeper"},
		{string(cassandraOptionsSupported()), 9042, "cassandra"},
		{"ClickHouse server hello", 9000, "clickhouse"},
		{"KingbaseES FATAL password", 54321, "kingbase"},
		{"DM Database Server 8.0", 5236, "dm"},
		{"jraft nacos raft response", 7848, "nacos"},
		{"CONNECTED\nversion:1.2\nserver:ActiveMQ\n\n\x00", 61613, "activemq"},
		{"\x11\x01\x00\x00", 1801, "msmq"},
		{"NI_PONG\x00SAP", 50000, "sap-p4"},
		{"E\x00\x00\x00\x40SFATALpostgresC28P01", 5432, "postgresql"},
	}
	for _, tc := range cases {
		rec, ok := FromBanner(tc.raw, tc.port)
		if !ok || rec.Protocol != tc.want {
			t.Fatalf("raw %q port %d => %+v ok=%v want %s", tc.raw, tc.port, rec, ok, tc.want)
		}
	}
}

func tidbGreeting(version string) []byte {
	payload := append([]byte{0x0a}, []byte(version)...)
	payload = append(payload, 0x00, 0x01, 0x00, 0x00, 0x00)
	out := make([]byte, 4+len(payload))
	out[0] = byte(len(payload))
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload) >> 16)
	copy(out[4:], payload)
	return out
}

func cassandraOptionsSupported() []byte {
	body := []byte("CQL_VERSION PROTOCOL_VERSIONS")
	out := make([]byte, 9+len(body))
	out[0] = 0x84
	out[4] = 0x06
	binary.BigEndian.PutUint32(out[5:9], uint32(len(body)))
	copy(out[9:], body)
	return out
}

func rocketMQTestFrameBytes() []byte {
	header := []byte(`{"code":0,"opaque":1,"remark":"OK"}`)
	frameLen := 4 + len(header)
	out := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(header)))
	copy(out[8:], header)
	return out
}

func TestGenericBannersStayUnclassified(t *testing.T) {
	for _, raw := range []string{
		`HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"lab","tagline":"You Know, for Search"}`,
		"HTTP/1.1 401\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\n",
		"HTTP/1.1 200\r\n\r\n<html>nacos</html>",
		"OK\r\n",
	} {
		if rec, ok := FromBanner(raw, 9200); ok {
			t.Fatalf("generic banner should stay unclassified, got %+v", rec)
		}
	}
}

func TestDubboGenericOKDoesNotClassifyOnDefaultPort(t *testing.T) {
	if rec, ok := FromBanner("OK\r\n", 20880); ok {
		t.Fatalf("generic OK should not classify as Dubbo on default port, got %+v", rec)
	}
}
