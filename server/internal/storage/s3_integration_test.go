package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

func TestS3StoreIntegration(t *testing.T) {
	endpoint := os.Getenv("ARGUS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("ARGUS_TEST_S3_ENDPOINT is not configured")
	}
	store, err := NewS3Store(context.Background(), S3Config{
		Endpoint:  endpoint,
		Region:    "us-east-1",
		Bucket:    os.Getenv("ARGUS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("ARGUS_TEST_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("ARGUS_TEST_S3_SECRET_KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "integration/tenant/content"
	want := []byte("yaksha-exp-object")
	object, err := store.Put(ctx, key, bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if object.Backend != "s3" || object.Size != int64(len(want)) {
		t.Fatalf("unexpected object: %#v", object)
	}
	reader, opened, err := store.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, want) || opened.Size != object.Size {
		t.Fatalf("unexpected object read: got=%q object=%#v readErr=%v closeErr=%v", got, opened, readErr, closeErr)
	}
	listed, err := store.List(ctx, "integration/")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Key != key {
		t.Fatalf("unexpected object list: %#v", listed)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Exists(ctx, key); err != nil || exists {
		t.Fatalf("object should be deleted: exists=%v err=%v", exists, err)
	}
}
