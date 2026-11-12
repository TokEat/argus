package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestValidatePSKAcceptsMatchingKey(t *testing.T) {
	server := NewServer(0)
	server.SetPSK("cluster-psk")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-psk", "cluster-psk"))
	if err := server.validatePSK(ctx); err != nil {
		t.Fatalf("expected matching PSK to pass: %v", err)
	}
}

func TestValidatePSKRejectsMismatchAndMissing(t *testing.T) {
	server := NewServer(0)
	server.SetPSK("cluster-psk")
	wrong := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-psk", "other"))
	if err := server.validatePSK(wrong); err == nil {
		t.Fatal("expected mismatched PSK to fail")
	}
	if err := server.validatePSK(context.Background()); err == nil {
		t.Fatal("expected missing metadata to fail")
	}
}

func TestAgentPSKMissingFailsClosedWithoutDev(t *testing.T) {
	server := NewServer(0)
	if !server.agentPSKMissing() {
		t.Fatal("empty PSK must be rejected outside --dev")
	}
	server.SetAllowOpenPSK(true)
	if server.agentPSKMissing() {
		t.Fatal("--dev should allow empty PSK")
	}
	server.SetAllowOpenPSK(false)
	server.SetPSK("configured")
	if server.agentPSKMissing() {
		t.Fatal("configured PSK must not be treated as missing")
	}
}
