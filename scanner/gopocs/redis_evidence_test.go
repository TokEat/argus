package gopocs

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestRedisUnauthPublishesSuccessfulRawExchangeWithoutAuditDependency(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 64)
		count, readErr := connection.Read(buffer)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if string(buffer[:count]) != "info\r\n" {
			serverErr <- &unexpectedRedisRequest{got: string(buffer[:count])}
			return
		}
		_, writeErr := connection.Write([]byte("$32\r\nredis_version:7.2.0\r\nrole:master\r\n"))
		serverErr <- writeErr
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var finding structs.OutputMessage
	info := &structs.HostInfo{
		Host:  host,
		Ports: port,
		Emit: func(message structs.OutputMessage) {
			finding = message
		},
	}
	matched, scanErr := RedisUnauth(info)
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if !matched {
		t.Fatal("Redis unauthenticated verification did not match")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if len(finding.GoPoc.Exchanges) != 1 {
		t.Fatalf("GoPoc exchanges = %#v, want one", finding.GoPoc.Exchanges)
	}
	want := binaryGoPocExchange("Redis INFO verification", []byte("info\r\n"), []byte("$32\r\nredis_version:7.2.0\r\nrole:master\r\n"))
	if !reflect.DeepEqual(finding.GoPoc.Exchanges[0], want) {
		t.Fatalf("unexpected Redis evidence: got %#v want %#v", finding.GoPoc.Exchanges[0], want)
	}
}

func TestRedisAuthPublishesOnlySuccessfulCredentialExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	const password = "verified-secret"
	requestBytes := []byte("auth " + password + "\r\n")
	responseBytes := []byte("+OK\r\n")
	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 128)
		count, readErr := connection.Read(buffer)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if string(buffer[:count]) != string(requestBytes) {
			serverErr <- &unexpectedRedisRequest{got: string(buffer[:count])}
			return
		}
		_, writeErr := connection.Write(responseBytes)
		serverErr <- writeErr
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var finding structs.OutputMessage
	info := &structs.HostInfo{
		Host:  host,
		Ports: port,
		Emit: func(message structs.OutputMessage) {
			finding = message
		},
	}
	matched, scanErr := RedisConn(info, password)
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if !matched {
		t.Fatal("Redis authenticated verification did not match")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	want := []structs.GoPocExchange{
		binaryGoPocExchange("Redis AUTH verification", requestBytes, responseBytes),
	}
	if !reflect.DeepEqual(finding.GoPoc.Exchanges, want) {
		t.Fatalf("unexpected Redis AUTH evidence: got %#v want %#v", finding.GoPoc.Exchanges, want)
	}
}

type unexpectedRedisRequest struct{ got string }

func (err *unexpectedRedisRequest) Error() string {
	return "unexpected Redis request: " + err.got
}
