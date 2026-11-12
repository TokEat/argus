package gopocs

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/gopocs/telnetlib"
	"github.com/TokEat/argus/scanner/structs"
)

type telnetFindingCapture struct {
	emitted []structs.OutputMessage
	stored  []structs.GoPocsResultType
}

func (capture *telnetFindingCapture) hostInfo(t *testing.T, address string) *structs.HostInfo {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return &structs.HostInfo{
		Host:  host,
		Ports: port,
		Emit: func(message structs.OutputMessage) {
			capture.emitted = append(capture.emitted, message)
		},
		WriteResult: func(result structs.GoPocsResultType) {
			capture.stored = append(capture.stored, result)
		},
	}
}

func (capture *telnetFindingCapture) assertFinding(t *testing.T, expected []telnetlib.RawExchange) {
	t.Helper()
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	if !reflect.DeepEqual(capture.emitted[0].GoPoc, capture.stored[0]) {
		t.Fatalf("OutputMessage and writeResult differ:\nemitted: %#v\nstored:  %#v", capture.emitted[0].GoPoc, capture.stored[0])
	}
	want := telnetGoPocExchanges(expected)
	if !reflect.DeepEqual(capture.stored[0].Exchanges, want) {
		t.Fatalf("Telnet exchanges = %#v, want %#v", capture.stored[0].Exchanges, want)
	}
	for _, exchange := range capture.stored[0].Exchanges {
		if exchange.Encoding != "hex-dump" {
			t.Fatalf("Telnet evidence encoding = %q, want hex-dump", exchange.Encoding)
		}
	}
}

func (capture *telnetFindingCapture) assertFindingEvents(t *testing.T, expected []telnetlib.RawExchange) {
	t.Helper()
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	if !reflect.DeepEqual(capture.emitted[0].GoPoc, capture.stored[0]) {
		t.Fatalf("OutputMessage and writeResult differ:\nemitted: %#v\nstored:  %#v", capture.emitted[0].GoPoc, capture.stored[0])
	}
	actual := capture.stored[0].Exchanges
	if len(actual) != len(expected) {
		t.Fatalf("Telnet exchange count = %d, want %d: %#v", len(actual), len(expected), actual)
	}
	matched := make([]bool, len(actual))
	for _, raw := range expected {
		want := binaryGoPocExchange("", raw.Request, raw.Response)
		found := false
		for index, exchange := range actual {
			if matched[index] || exchange.Request != want.Request || exchange.Response != want.Response {
				continue
			}
			matched[index] = true
			found = true
			break
		}
		if !found {
			t.Fatalf("Telnet evidence is missing request=%q response=%q: %#v", want.Request, want.Response, actual)
		}
	}
	for _, exchange := range actual {
		if exchange.Encoding != "hex-dump" {
			t.Fatalf("Telnet evidence encoding = %q, want hex-dump", exchange.Encoding)
		}
	}
}

func TestTelnetUnauthorizedPublishesConnectionReadsAndAutomaticNegotiationWrite(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	banner := append([]byte{telnetlib.IAC, telnetlib.WILL, telnetlib.ECHO}, []byte("# ")...)
	reply := []byte{telnetlib.IAC, telnetlib.DO, telnetlib.ECHO}
	done := serveTelnetScript(t, listener, func(connection net.Conn) error {
		if _, err := connection.Write(banner); err != nil {
			return err
		}
		return readExactTelnetWrite(connection, reply)
	})

	var capture telnetFindingCapture
	if err := TelnetScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitTelnetScript(t, done)
	capture.assertFinding(t, []telnetlib.RawExchange{
		{Response: banner},
		{Request: reply},
	})
}

func TestTelnetUsernamePasswordPublishesOnlyFinalSuccessfulConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	loginPrompt := []byte("login:")
	passwordPrompt := []byte("Password:")
	username := []byte("admin\r\x00")
	wrongPassword := []byte("wrong\r\x00")
	correctPassword := []byte("verified-secret\r\x00")
	failedResponse := []byte("Login failed\n")
	successResponse := []byte("# ")
	done := serveTelnetScript(t, listener,
		func(connection net.Conn) error {
			_, err := connection.Write(loginPrompt)
			return err
		},
		consumeAuthTimeoutProbe,
		func(connection net.Conn) error {
			return serveTelnetCredentialAttempt(connection, loginPrompt, passwordPrompt, username, wrongPassword, failedResponse)
		},
		func(connection net.Conn) error {
			return serveTelnetCredentialAttempt(connection, loginPrompt, passwordPrompt, username, correctPassword, successResponse)
		},
	)

	var capture telnetFindingCapture
	info := capture.hostInfo(t, listener.Addr().String())
	info.UserPass = []string{"admin : wrong", "admin : verified-secret"}
	if err := TelnetScan(info); err != nil {
		t.Fatal(err)
	}
	waitTelnetScript(t, done)
	// Reads and writes are recorded after their respective socket operation
	// completes. A peer response can therefore be recorded before the write
	// goroutine records the request that triggered it. Assert the complete
	// successful-session evidence without depending on scheduler ordering.
	capture.assertFindingEvents(t, []telnetlib.RawExchange{
		{Response: loginPrompt},
		{Request: username},
		{Response: passwordPrompt},
		{Request: correctPassword},
		{Response: successResponse},
	})
	for _, exchange := range capture.stored[0].Exchanges {
		if strings.Contains(exchange.Request, "wrong") || strings.Contains(exchange.Response, "Login failed") {
			t.Fatalf("failed credential exchange leaked into finding: %#v", exchange)
		}
	}
}

func TestTelnetOnlyPasswordPublishesSuccessfulConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	passwordPrompt := []byte("Password:")
	password := []byte("verified-secret\r\x00")
	successResponse := []byte("# ")
	done := serveTelnetScript(t, listener,
		func(connection net.Conn) error {
			_, err := connection.Write(passwordPrompt)
			return err
		},
		consumeAuthTimeoutProbe,
		func(connection net.Conn) error {
			if _, err := connection.Write(passwordPrompt); err != nil {
				return err
			}
			if err := readExactTelnetWrite(connection, password); err != nil {
				return err
			}
			_, err := connection.Write(successResponse)
			return err
		},
	)

	var capture telnetFindingCapture
	info := capture.hostInfo(t, listener.Addr().String())
	info.UserPass = []string{"ignored : verified-secret"}
	if err := TelnetScan(info); err != nil {
		t.Fatal(err)
	}
	waitTelnetScript(t, done)
	capture.assertFindingEvents(t, []telnetlib.RawExchange{
		{Response: passwordPrompt},
		{Request: password},
		{Response: successResponse},
	})
}

// consumeAuthTimeoutProbe absorbs the single TCP RTT probe TelnetScan opens
// after the initial banner connection and before its cracking loop; the probe
// closes without exchanging any data.
func consumeAuthTimeoutProbe(connection net.Conn) error {
	return nil
}

func serveTelnetScript(t *testing.T, listener net.Listener, handlers ...func(net.Conn) error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for index, handler := range handlers {
			connection, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			err = handler(connection)
			_ = connection.Close()
			if err != nil {
				done <- fmt.Errorf("connection %d: %w", index+1, err)
				return
			}
		}
		done <- nil
	}()
	return done
}

func serveTelnetCredentialAttempt(connection net.Conn, loginPrompt, passwordPrompt, username, password, response []byte) error {
	if _, err := connection.Write(loginPrompt); err != nil {
		return err
	}
	if err := readExactTelnetWrite(connection, username); err != nil {
		return err
	}
	if _, err := connection.Write(passwordPrompt); err != nil {
		return err
	}
	if err := readExactTelnetWrite(connection, password); err != nil {
		return err
	}
	_, err := connection.Write(response)
	return err
}

func readExactTelnetWrite(connection net.Conn, expected []byte) error {
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(connection, actual); err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("Telnet write = %x, want %x", actual, expected)
	}
	return nil
}

func waitTelnetScript(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Telnet loopback server did not finish")
	}
}
