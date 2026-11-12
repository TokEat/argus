package gopocs

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/structs"
)

type goPocCapture struct {
	emitted []structs.OutputMessage
	stored  []structs.GoPocsResultType
}

func (capture *goPocCapture) hostInfo(t *testing.T, address string) *structs.HostInfo {
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

func (capture *goPocCapture) assertSingleFinding(t *testing.T, want []structs.GoPocExchange) {
	t.Helper()
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	if !reflect.DeepEqual(capture.emitted[0].GoPoc, capture.stored[0]) {
		t.Fatalf("OutputMessage and writeResult differ:\nemitted: %#v\nstored:  %#v", capture.emitted[0].GoPoc, capture.stored[0])
	}
	if !reflect.DeepEqual(capture.stored[0].Exchanges, want) {
		t.Fatalf("successful exchanges = %#v, want %#v", capture.stored[0].Exchanges, want)
	}
}

func (capture *goPocCapture) assertNoFinding(t *testing.T) {
	t.Helper()
	if len(capture.emitted) != 0 || len(capture.stored) != 0 {
		t.Fatalf("failed verification published evidence: emitted=%#v stored=%#v", capture.emitted, capture.stored)
	}
}

func startScriptedListener(t *testing.T, script func(net.Listener) error) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- script(listener)
	}()
	return listener, done
}

func waitForScript(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scripted server did not finish")
	}
}

type wireStep struct {
	request  []byte
	response []byte
}

func serveWireSteps(listener net.Listener, steps []wireStep) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	for index, step := range steps {
		request := make([]byte, len(step.request))
		if _, err := io.ReadFull(connection, request); err != nil {
			return fmt.Errorf("read step %d: %w", index+1, err)
		}
		if !reflect.DeepEqual(request, step.request) {
			return fmt.Errorf("step %d request = %x, want %x", index+1, request, step.request)
		}
		if _, err := connection.Write(step.response); err != nil {
			return fmt.Errorf("write step %d: %w", index+1, err)
		}
	}
	return nil
}

func TestJDWPPublishesSuccessfulOrderedRawExchanges(t *testing.T) {
	handshakeRequest := []byte("JDWP-Handshake")
	idSizesRequest := []byte("\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x07")
	versionRequest := []byte("\x00\x00\x00\x0b\x00\x00\x00\x03\x00\x01\x01")
	handshakeResponse := []byte("JDWP-Handshake")
	idSizesResponse := []byte("idsizes-response")
	versionResponse := []byte("0123456789abcdeJava Debug Wire Protocol 17")
	steps := []wireStep{
		{request: handshakeRequest, response: handshakeResponse},
		{request: idSizesRequest, response: idSizesResponse},
		{request: versionRequest, response: versionResponse},
	}

	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveWireSteps(listener, steps)
	})
	defer listener.Close()

	var capture goPocCapture
	if err := JDWPScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("JDWP handshake", handshakeRequest, handshakeResponse),
		binaryGoPocExchange("JDWP VirtualMachine.IDSizes", idSizesRequest, idSizesResponse),
		binaryGoPocExchange("JDWP VirtualMachine.Version", versionRequest, versionResponse),
	})
}

func TestJDWPDoesNotPublishFailedHandshakeEvidence(t *testing.T) {
	steps := []wireStep{{request: []byte("JDWP-Handshake"), response: []byte("not-jdwp")}}
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveWireSteps(listener, steps)
	})
	defer listener.Close()

	var capture goPocCapture
	if err := JDWPScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertNoFinding(t)
}

func TestMemcachedPublishesOnlySuccessfulRawExchange(t *testing.T) {
	request := []byte("stats\n")
	response := []byte("STAT version 1.6.22\r\nEND\r\n")
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveWireSteps(listener, []wireStep{{request: request, response: response}})
	})
	defer listener.Close()

	var capture goPocCapture
	if err := MemcachedScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("Memcached stats verification", request, response),
	})
}

func TestMemcachedDoesNotPublishFailedVerificationEvidence(t *testing.T) {
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveWireSteps(listener, []wireStep{{request: []byte("stats\n"), response: []byte("ERROR\r\n")}})
	})
	defer listener.Close()

	var capture goPocCapture
	if err := MemcachedScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertNoFinding(t)
}

func readMongoPacket(connection net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint32(header))
	if length < 16 || length > 1<<20 {
		return nil, fmt.Errorf("invalid MongoDB packet length %d", length)
	}
	packet := make([]byte, length)
	copy(packet, header)
	if _, err := io.ReadFull(connection, packet[len(header):]); err != nil {
		return nil, err
	}
	return packet, nil
}

func mongoOpcode(packet []byte) int32 {
	return int32(binary.LittleEndian.Uint32(packet[12:16]))
}

func TestMongoDBPublishesActualOPMSGExchange(t *testing.T) {
	response := []byte("mongo reply: totalLinesWritten")
	var actualRequest []byte
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
		actualRequest, err = readMongoPacket(connection)
		if err != nil {
			return err
		}
		if got := mongoOpcode(actualRequest); got != 2013 {
			return fmt.Errorf("MongoDB opcode = %d, want OP_MSG (2013)", got)
		}
		_, err = connection.Write(response)
		return err
	})
	defer listener.Close()

	var capture goPocCapture
	matched, err := MongodbUnauth(capture.hostInfo(t, listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("MongoDB OP_MSG verification did not match")
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("MongoDB OP_MSG unauthenticated verification", actualRequest, response),
	})
}

func TestMongoDBFallbackPublishesOnlyActualOPQUERYExchange(t *testing.T) {
	response := []byte("legacy mongo reply: totalLinesWritten")
	var fallbackRequest []byte
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		first, err := listener.Accept()
		if err != nil {
			return err
		}
		_ = first.SetDeadline(time.Now().Add(4 * time.Second))
		firstRequest, err := readMongoPacket(first)
		if err != nil {
			first.Close()
			return err
		}
		if got := mongoOpcode(firstRequest); got != 2013 {
			first.Close()
			return fmt.Errorf("first MongoDB opcode = %d, want OP_MSG (2013)", got)
		}
		if err := first.Close(); err != nil {
			return err
		}

		fallback, err := listener.Accept()
		if err != nil {
			return err
		}
		defer fallback.Close()
		_ = fallback.SetDeadline(time.Now().Add(4 * time.Second))
		fallbackRequest, err = readMongoPacket(fallback)
		if err != nil {
			return err
		}
		if got := mongoOpcode(fallbackRequest); got != 2004 {
			return fmt.Errorf("fallback MongoDB opcode = %d, want OP_QUERY (2004)", got)
		}
		_, err = fallback.Write(response)
		return err
	})
	defer listener.Close()

	var capture goPocCapture
	matched, err := MongodbUnauth(capture.hostInfo(t, listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("MongoDB OP_QUERY fallback verification did not match")
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("MongoDB OP_QUERY unauthenticated verification", fallbackRequest, response),
	})
}

func TestMongoDBDoesNotPublishFailedVerificationEvidence(t *testing.T) {
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := readMongoPacket(connection); err != nil {
			return err
		}
		_, err = connection.Write([]byte("MongoDB response without the unauthenticated marker"))
		return err
	})
	defer listener.Close()

	var capture goPocCapture
	matched, err := MongodbUnauth(capture.hostInfo(t, listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("MongoDB failed verification unexpectedly matched")
	}
	waitForScript(t, done)
	capture.assertNoFinding(t)
}
