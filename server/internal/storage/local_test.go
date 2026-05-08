package storage

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestLocalStorePutOpenListExists(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()
	obj, err := store.Put(ctx, "release/agent.bin", strings.NewReader("agent"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if obj.Key != "release/agent.bin" || obj.Size != 5 || obj.Backend != "local" {
		t.Fatalf("unexpected object: %+v", obj)
	}
	if _, ok, err := store.Exists(ctx, "release/agent.bin"); err != nil || !ok {
		t.Fatalf("Exists ok=%v err=%v", ok, err)
	}
	reader, opened, err := store.Open(ctx, "release/agent.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if opened.Key != obj.Key || string(data) != "agent" {
		t.Fatalf("unexpected opened object=%+v data=%q", opened, string(data))
	}
	objects, err := store.List(ctx, "release")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 1 || objects[0].Key != "release/agent.bin" {
		t.Fatalf("unexpected list: %+v", objects)
	}
}

func TestLocalStoreRejectsEscapingKeys(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	if _, err := store.Put(context.Background(), "../agent.bin", strings.NewReader("agent")); err == nil {
		t.Fatal("expected escaping key to be rejected")
	}
}
