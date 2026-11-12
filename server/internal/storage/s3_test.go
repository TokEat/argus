package storage

import (
	"context"
	"strings"
	"testing"
)

func TestS3StoreRejectsMissingConfigurationWithoutEchoingCredentials(t *testing.T) {
	const secret = "do-not-echo-this-secret"
	_, err := NewS3Store(context.Background(), S3Config{Endpoint: "http://127.0.0.1:9000", AccessKey: "application", SecretKey: secret})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing bucket should fail closed: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("configuration error exposed MinIO credential: %v", err)
	}
}
