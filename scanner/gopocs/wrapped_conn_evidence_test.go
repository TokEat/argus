package gopocs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/structs"
	"github.com/tomatome/grdp/glog"
)

func TestCaptureSuccessfulSessionEvidencePreservesExactIOOrder(t *testing.T) {
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		request := make([]byte, 3)
		if _, err := io.ReadFull(server, request); err != nil {
			serverErr <- err
			return
		}
		if !reflect.DeepEqual(request, []byte{0x00, 0xff, 0x41}) {
			serverErr <- fmt.Errorf("first request = %x", request)
			return
		}
		if _, err := server.Write([]byte{0xfe, 0x42}); err != nil {
			serverErr <- err
			return
		}
		request = make([]byte, 2)
		if _, err := io.ReadFull(server, request); err != nil {
			serverErr <- err
			return
		}
		if !reflect.DeepEqual(request, []byte{0x43, 0x44}) {
			serverErr <- fmt.Errorf("second request = %x", request)
			return
		}
		_, err := server.Write([]byte{0x45})
		serverErr <- err
	}()

	exchanges, err := captureSuccessfulSessionEvidence(client, "test", 64, func(conn net.Conn) error {
		if _, err := conn.Write([]byte{0x00, 0xff, 0x41}); err != nil {
			return err
		}
		response := make([]byte, 2)
		if _, err := io.ReadFull(conn, response); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{0x43, 0x44}); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, response[:1])
		return err
	})
	if err != nil {
		t.Fatalf("capture successful session: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("pipe server: %v", err)
	}

	want := []structs.GoPocExchange{
		binaryGoPocExchange("test wire I/O #1 request", []byte{0x00, 0xff, 0x41}, nil),
		binaryGoPocExchange("test wire I/O #2 response", nil, []byte{0xfe, 0x42}),
		binaryGoPocExchange("test wire I/O #3 request", []byte{0x43, 0x44}, nil),
		binaryGoPocExchange("test wire I/O #4 response", nil, []byte{0x45}),
	}
	if !reflect.DeepEqual(exchanges, want) {
		t.Fatalf("exchanges = %#v, want %#v", exchanges, want)
	}
}

func TestCaptureSuccessfulSessionEvidenceDiscardsFailedAttempt(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.CopyN(io.Discard, server, 3)
	}()

	authErr := errors.New("credential rejected")
	exchanges, err := captureSuccessfulSessionEvidence(client, "test", 64, func(conn net.Conn) error {
		_, _ = conn.Write([]byte("bad"))
		return authErr
	})
	if !errors.Is(err, authErr) {
		t.Fatalf("error = %v, want credential rejection", err)
	}
	if exchanges != nil {
		t.Fatalf("failed attempt leaked evidence: %#v", exchanges)
	}
}

func TestCaptureSuccessfulSessionEvidenceLimitFailsClosed(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.CopyN(io.Discard, server, 4)
	}()

	exchanges, err := captureSuccessfulSessionEvidence(client, "test", 3, func(conn net.Conn) error {
		_, writeErr := conn.Write([]byte("four"))
		return writeErr
	})
	if !errors.Is(err, errSuccessfulSessionEvidenceLimit) {
		t.Fatalf("error = %v, want evidence limit error", err)
	}
	if exchanges != nil {
		t.Fatalf("over-limit session published partial evidence: %#v", exchanges)
	}
}

func TestOverLimitFailedAttemptReturnsAuthenticationErrorWithoutEvidence(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.CopyN(io.Discard, server, 4)
	}()

	authErr := errors.New("credential rejected")
	exchanges, err := captureSuccessfulSessionEvidence(client, "test", 3, func(conn net.Conn) error {
		if _, writeErr := conn.Write([]byte("four")); writeErr != nil {
			return writeErr
		}
		return authErr
	})
	if !errors.Is(err, authErr) || errors.Is(err, errSuccessfulSessionEvidenceLimit) {
		t.Fatalf("error = %v, want only credential rejection", err)
	}
	if exchanges != nil {
		t.Fatalf("failed attempt leaked evidence: %#v", exchanges)
	}
}

func TestCredentialScansStopAfterEvidenceFailure(t *testing.T) {
	evidenceErr := fmt.Errorf("%w (limit: 1 bytes)", errSuccessfulSessionEvidenceLimit)
	tests := []struct {
		name string
		run  func(*int) error
	}{
		{
			name: "VNC",
			run: func(calls *int) error {
				return vncScanWithConnector(&structs.HostInfo{Host: "127.0.0.1", Ports: "5900"}, func(*structs.HostInfo, string) (bool, error) {
					*calls++
					return false, evidenceErr
				})
			},
		},
		{
			name: "SMB",
			run: func(calls *int) error {
				info := &structs.HostInfo{Host: "127.0.0.1", Ports: "445", UserPass: []string{"one : a", "two : b"}}
				return smbScanWithConnector(info, func(*structs.HostInfo, string, string) (bool, error) {
					*calls++
					return false, evidenceErr
				})
			},
		},
		{
			name: "RDP",
			run: func(calls *int) error {
				info := &structs.HostInfo{Host: "127.0.0.1", Ports: "3389", UserPass: []string{"one : a", "two : b"}}
				return rdpScanWithConnector(info, func(string, string, string, string, int, int64) (bool, []structs.GoPocExchange, error) {
					*calls++
					return false, nil, evidenceErr
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := test.run(&calls)
			if !errors.Is(err, errSuccessfulSessionEvidenceLimit) {
				t.Fatalf("scan error = %v, want evidence failure", err)
			}
			if calls != 1 {
				t.Fatalf("credential attempts = %d, want 1", calls)
			}
		})
	}
}

func TestVNCAndSMBPublishSameSuccessfulPocResult(t *testing.T) {
	tests := []struct {
		name  string
		label string
		run   func(*structs.HostInfo, net.Conn, func(net.Conn) error) (bool, error)
	}{
		{
			name:  "VNC",
			label: "VNC authentication",
			run: func(info *structs.HostInfo, conn net.Conn, operation func(net.Conn) error) (bool, error) {
				return vncConnWithEvidence(info, "secret", conn, 64, func(conn net.Conn, _ string) error {
					return operation(conn)
				})
			},
		},
		{
			name:  "SMB",
			label: "SMB authentication",
			run: func(info *structs.HostInfo, conn net.Conn, operation func(net.Conn) error) (bool, error) {
				return smblConnWithEvidence(info, "user", "secret", conn, 64, func(conn net.Conn, _, _ string) ([]string, error) {
					return []string{"share"}, operation(conn)
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				request := make([]byte, 2)
				_, _ = io.ReadFull(server, request)
				_, _ = server.Write([]byte{0x00, 0xff})
			}()

			var emitted structs.OutputMessage
			var stored structs.GoPocsResultType
			info := &structs.HostInfo{
				Host:  "127.0.0.1",
				Ports: "1",
				Emit: func(message structs.OutputMessage) {
					emitted = message
				},
				WriteResult: func(result structs.GoPocsResultType) {
					stored = result
				},
			}
			flag, err := test.run(info, client, func(conn net.Conn) error {
				if _, err := conn.Write([]byte{0x41, 0x42}); err != nil {
					return err
				}
				response := make([]byte, 2)
				_, err := io.ReadFull(conn, response)
				return err
			})
			if err != nil || !flag {
				t.Fatalf("successful session = %v, %v", flag, err)
			}
			if !reflect.DeepEqual(emitted.GoPoc, stored) {
				t.Fatalf("OutputMessage and writeResult differ:\nemitted: %#v\nstored:  %#v", emitted.GoPoc, stored)
			}
			want := []structs.GoPocExchange{
				binaryGoPocExchange(test.label+" wire I/O #1 request", []byte{0x41, 0x42}, nil),
				binaryGoPocExchange(test.label+" wire I/O #2 response", nil, []byte{0x00, 0xff}),
			}
			if !reflect.DeepEqual(stored.Exchanges, want) {
				t.Fatalf("exchanges = %#v, want %#v", stored.Exchanges, want)
			}
		})
	}
}

func TestRDPClientRecordsInjectedSuccessfulSession(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		request := make([]byte, 3)
		_, _ = io.ReadFull(server, request)
		_, _ = server.Write([]byte{0xfe, 0xff})
	}()

	rdpClient := newClientWithDialer("127.0.0.1:3389", glog.NONE, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return client, nil
	})
	exchanges, err := rdpClient.loginWithEvidenceUsing(6, 64, func(conn net.Conn) error {
		if _, err := conn.Write([]byte{0x01, 0x02, 0x03}); err != nil {
			return err
		}
		response := make([]byte, 2)
		_, err := io.ReadFull(conn, response)
		return err
	})
	if err != nil {
		t.Fatalf("RDP evidence capture: %v", err)
	}
	want := []structs.GoPocExchange{
		binaryGoPocExchange("RDP authentication (TLS sessions are ciphertext) wire I/O #1 request", []byte{0x01, 0x02, 0x03}, nil),
		binaryGoPocExchange("RDP authentication (TLS sessions are ciphertext) wire I/O #2 response", nil, []byte{0xfe, 0xff}),
	}
	if !reflect.DeepEqual(exchanges, want) {
		t.Fatalf("exchanges = %#v, want %#v", exchanges, want)
	}
}
