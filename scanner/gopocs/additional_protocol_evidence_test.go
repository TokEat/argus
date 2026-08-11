package gopocs

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestADBUnauthorizedPublishesActualCNXNExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	response := append(append([]byte("CNXN"), make([]byte, 20)...), []byte("ro.product.name=argus-test\x00")...)
	requestBytes := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 1024)
		count, readErr := connection.Read(buffer)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		requestBytes <- append([]byte(nil), buffer[:count]...)
		_, writeErr := connection.Write(response)
		serverErr <- writeErr
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var finding structs.OutputMessage
	info := &structs.HostInfo{Emit: func(message structs.OutputMessage) { finding = message }}
	scanErr, result := aDBUnauthorized(info, host, port)
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if result == "" {
		t.Fatal("ADB unauthorized verification returned no result")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	request := <-requestBytes
	want := []structs.GoPocExchange{
		binaryGoPocExchange("ADB CNXN authorization verification", request, response),
	}
	if !reflect.DeepEqual(finding.GoPoc.Exchanges, want) {
		t.Fatalf("ADB exchanges = %#v, want %#v", finding.GoPoc.Exchanges, want)
	}
}

func TestTelnetCVEPublishesResponseOnlyNegotiationEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	response := []byte{0xff, 0xfd, 0x24, 0xff, 0xfb, 0x01}
	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_, writeErr := connection.Write(response)
		serverErr <- writeErr
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var finding structs.OutputMessage
	info := &structs.HostInfo{Host: host, Ports: port, Emit: func(message structs.OutputMessage) { finding = message }}
	if err := TelnetCVEScan(info); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	want := binaryGoPocExchange("Telnet negotiation vulnerability response", nil, response)
	if len(finding.GoPoc.Exchanges) != 1 || finding.GoPoc.Exchanges[0] != want {
		t.Fatalf("Telnet CVE exchange = %#v, want %#v", finding.GoPoc.Exchanges, want)
	}
}
