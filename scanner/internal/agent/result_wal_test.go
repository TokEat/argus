package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

func TestWALAppendReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir, "task-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []*pb.ScanResult{
		{TaskId: "task-1", PayloadType: "web_info", Payload: []byte(`{"a":1}`), Timestamp: 100},
		{TaskId: "task-1", PayloadType: "finger", Payload: []byte(`{"b":2}`), Timestamp: 200},
		{TaskId: "task-1", PayloadType: "scan_progress", Payload: []byte(`{"done":3}`), Timestamp: 300},
	}
	for _, res := range want {
		if err := w.Append(res); err != nil {
			t.Fatal(err)
		}
	}
	if w.Count() != len(want) {
		t.Fatalf("Count() = %d, want %d", w.Count(), len(want))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := OpenWALForReplay(dir, "task-1")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []*pb.ScanResult
	if err := r.Replay(0, func(res *pb.ScanResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("replayed %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].PayloadType != want[i].PayloadType || string(got[i].Payload) != string(want[i].Payload) || got[i].Timestamp != want[i].Timestamp {
			t.Errorf("frame %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestWALReplayFromOffset(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir, "task-off")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Append(&pb.ScanResult{TaskId: "task-off", PayloadType: "x", Timestamp: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()

	r, _ := OpenWALForReplay(dir, "task-off")
	defer r.Close()
	var got []int64
	if err := r.Replay(3, func(res *pb.ScanResult) error {
		got = append(got, res.Timestamp)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 3 || got[1] != 4 {
		t.Fatalf("Replay(3) = %v, want [3 4]", got)
	}
}

func TestWALDiscardRemovesFile(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir, "task-discard")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(&pb.ScanResult{TaskId: "task-discard"}); err != nil {
		t.Fatal(err)
	}
	path := w.Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("wal file should exist before discard: %v", err)
	}
	if err := w.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("wal file should be removed after discard, stat err=%v", err)
	}
}

func TestWALReplayToleratesTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir, "task-trunc")
	if err != nil {
		t.Fatal(err)
	}
	good := &pb.ScanResult{TaskId: "task-trunc", PayloadType: "web_info", Payload: []byte("ok")}
	if err := w.Append(good); err != nil {
		t.Fatal(err)
	}
	// 直接往文件里写半个帧头，模拟崩溃残留。
	if _, err := w.file.Write([]byte{0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	r, _ := OpenWALForReplay(dir, "task-trunc")
	defer r.Close()
	var got []*pb.ScanResult
	if err := r.Replay(0, func(res *pb.ScanResult) error {
		got = append(got, res)
		return nil
	}); err != nil {
		t.Fatalf("replay should tolerate truncated tail: %v", err)
	}
	if len(got) != 1 || string(got[0].Payload) != "ok" {
		t.Fatalf("expected only the complete frame, got %+v", got)
	}
}

func TestCleanupOrphanWALs(t *testing.T) {
	dir := t.TempDir()
	// 旧文件（应被清理）。
	old := filepath.Join(dir, "old.wal")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	// 新文件（应保留）。
	fresh := filepath.Join(dir, "fresh.wal")
	if err := os.WriteFile(fresh, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 非 .wal 文件（应保留）。
	other := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(other, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupOrphanWALs(dir, time.Now())

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("orphan old.wal should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh.wal should be kept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("non-wal file should be kept: %v", err)
	}
}
