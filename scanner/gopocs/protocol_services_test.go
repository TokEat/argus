package gopocs

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestProtocolValidationScansPublishEvidence(t *testing.T) {
	tests := []struct {
		name    string
		scan    func(*structs.HostInfo) error
		steps   []wireStep
		pocName string
	}{
		{
			name:    "rocketmq-broker",
			scan:    RocketMQBrokerScan,
			steps:   []wireStep{{request: rocketMQRequest(26), response: rocketMQResponseFrame(0, []byte("brokerConfig=true\n"))}},
			pocName: "RocketMQ-Broker-Unauthorized",
		},
		{
			name:    "rocketmq-namesrv",
			scan:    RocketMQNameServerScan,
			steps:   []wireStep{{request: rocketMQRequest(106), response: rocketMQResponseFrame(0, []byte("clusterInfo=true\n"))}},
			pocName: "RocketMQ-NameServer-Unauthorized",
		},
		{
			name: "rabbitmq-amqp",
			scan: RabbitMQAMQPScan,
			steps: []wireStep{
				{request: []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}, response: amqpMethodFrame([]byte{0x00, 0x0a, 0x00, 0x0a})},
				{request: amqpStartOKFrame(), response: amqpMethodFrame([]byte{0x00, 0x0a, 0x00, 0x1e})},
			},
			pocName: "RabbitMQ-AMQP-Anonymous",
		},
		{
			name:    "epmd",
			scan:    EPMDScan,
			steps:   []wireStep{{request: []byte{0x00, 0x01, 0x6e}, response: []byte("\x00\x00\x11\x11name rabbit at port 25672\n")}},
			pocName: "EPMD-Node-Exposure",
		},
		{
			name:    "cassandra",
			scan:    CassandraScan,
			steps:   []wireStep{{request: cassandraStartupRequest(), response: cassandraReadyFrame()}},
			pocName: "Cassandra-Unauthorized",
		},
		{
			name:    "clickhouse",
			scan:    ClickHouseScan,
			steps:   []wireStep{{request: clickHouseDefaultUserHello(), response: clickHouseHelloResponse()}},
			pocName: "ClickHouse-Unauthorized",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			listener, done := startScriptedListener(t, func(listener net.Listener) error {
				return serveWireSteps(listener, tt.steps)
			})
			defer listener.Close()

			var capture goPocCapture
			if err := tt.scan(capture.hostInfo(t, listener.Addr().String())); err != nil {
				t.Fatal(err)
			}
			waitForScript(t, done)
			assertFindingWithEvidence(t, capture, tt.pocName)
		})
	}
}

func TestProtocolValidationScansDoNotPublishOnMismatch(t *testing.T) {
	tests := []struct {
		name  string
		scan  func(*structs.HostInfo) error
		steps []wireStep
	}{
		{name: "rocketmq-broker", scan: RocketMQBrokerScan, steps: []wireStep{{request: rocketMQRequest(26), response: rocketMQResponseFrame(1, nil)}}},
		{name: "rocketmq-namesrv", scan: RocketMQNameServerScan, steps: []wireStep{{request: rocketMQRequest(106), response: rocketMQResponseFrame(1, nil)}}},
		{
			name: "rabbitmq-amqp",
			scan: RabbitMQAMQPScan,
			steps: []wireStep{
				{request: []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}, response: amqpMethodFrame([]byte{0x00, 0x0a, 0x00, 0x0a})},
				{request: amqpStartOKFrame(), response: amqpMethodFrame([]byte{0x00, 0x0a, 0x00, 0x32})},
			},
		},
		{name: "epmd", scan: EPMDScan, steps: []wireStep{{request: []byte{0x00, 0x01, 0x6e}, response: []byte("not epmd")}}},
		{name: "cassandra", scan: CassandraScan, steps: []wireStep{{request: cassandraStartupRequest(), response: cassandraAuthenticateFrame()}}},
		{name: "clickhouse", scan: ClickHouseScan, steps: []wireStep{{request: clickHouseDefaultUserHello(), response: clickHouseExceptionResponse()}}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			listener, done := startScriptedListener(t, func(listener net.Listener) error {
				return serveWireSteps(listener, tt.steps)
			})
			defer listener.Close()

			var capture goPocCapture
			if err := tt.scan(capture.hostInfo(t, listener.Addr().String())); err != nil {
				t.Fatal(err)
			}
			waitForScript(t, done)
			capture.assertNoFinding(t)
		})
	}
}

func assertFindingWithEvidence(t *testing.T, capture goPocCapture, pocName string) {
	t.Helper()
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	if capture.stored[0].PocName != pocName {
		t.Fatalf("PocName = %q, want %q", capture.stored[0].PocName, pocName)
	}
	if len(capture.stored[0].Exchanges) == 0 {
		t.Fatalf("finding %s has no protocol evidence", pocName)
	}
}

func rocketMQResponseFrame(code int, body []byte) []byte {
	header := []byte(fmt.Sprintf(`{"code":%d,"opaque":1,"remark":"OK"}`, code))
	frameLen := 4 + len(header) + len(body)
	out := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(header)))
	copy(out[8:], header)
	copy(out[8+len(header):], body)
	return out
}

func cassandraReadyFrame() []byte {
	return []byte{0x84, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
}

func cassandraAuthenticateFrame() []byte {
	return []byte{0x84, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00}
}

func clickHouseHelloResponse() []byte {
	return []byte{0x00, 0x0a, 'C', 'l', 'i', 'c', 'k', 'H', 'o', 'u', 's', 'e'}
}

func clickHouseExceptionResponse() []byte {
	return []byte{0x02, 'C', 'l', 'i', 'c', 'k', 'H', 'o', 'u', 's', 'e', ' ', 'a', 'u', 't', 'h', ' ', 'f', 'a', 'i', 'l', 'e', 'd'}
}
