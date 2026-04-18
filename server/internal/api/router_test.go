package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseTargetsAcceptsStringAndArray(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want []string
	}{
		{
			name: "string",
			raw:  json.RawMessage(`"127.0.0.1\nexample.com\n127.0.0.1"`),
			want: []string{"127.0.0.1", "example.com"},
		},
		{
			name: "array",
			raw:  json.RawMessage(`["127.0.0.1", "example.com", "127.0.0.1"]`),
			want: []string{"127.0.0.1", "example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTargets(tc.raw)
			if err != nil {
				t.Fatalf("parseTargets returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected targets: want=%v got=%v", tc.want, got)
			}
		})
	}
}

func TestNormalizeConfigPayload(t *testing.T) {
	tests := []struct {
		name    string
		raw     json.RawMessage
		want    string
		wantErr bool
	}{
		{
			name: "empty",
			raw:  nil,
			want: "{}",
		},
		{
			name: "json object",
			raw:  json.RawMessage(`{"web_threads":10}`),
			want: `{"web_threads":10}`,
		},
		{
			name: "json string",
			raw:  json.RawMessage(`"{\"web_threads\":10}"`),
			want: `{"web_threads":10}`,
		},
		{
			name:    "invalid json string",
			raw:     json.RawMessage(`"{invalid}"`),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeConfigPayload(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeConfigPayload returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("unexpected config payload: want=%s got=%s", tc.want, got)
			}
		})
	}
}
