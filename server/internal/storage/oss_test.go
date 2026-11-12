package storage

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/cloud"
)

type fakeStorageOSSUploader struct {
	files      map[string]string
	deletedKey string
}

func (f *fakeStorageOSSUploader) UploadFile(localPath, objectKey string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	f.files[objectKey] = string(data)
	return nil
}

func (f *fakeStorageOSSUploader) DownloadFile(objectKey, localPath string) error {
	data, ok := f.files[objectKey]
	if !ok {
		return os.ErrNotExist
	}
	return os.WriteFile(localPath, []byte(data), 0o644)
}

func (f *fakeStorageOSSUploader) GeneratePresignedURL(objectKey string, expiry time.Duration) (string, error) {
	return "https://example.com/" + objectKey, nil
}

func (f *fakeStorageOSSUploader) UploadAgentBinaries(releaseDir string) ([]cloud.OSSUploadResult, error) {
	return nil, nil
}

func (f *fakeStorageOSSUploader) TestConnection() error {
	return nil
}

func (f *fakeStorageOSSUploader) ListFiles(prefix string) ([]cloud.OSSFileInfo, error) {
	out := []cloud.OSSFileInfo{}
	for key, data := range f.files {
		if prefix == "." || strings.HasPrefix(key, prefix) {
			out = append(out, cloud.OSSFileInfo{Key: key, Size: int64(len(data)), LastModified: time.Unix(10, 0)})
		}
	}
	return out, nil
}

func (f *fakeStorageOSSUploader) DeleteFile(objectKey string) error {
	f.deletedKey = objectKey
	delete(f.files, objectKey)
	return nil
}

func TestOSSStorePutOpenExistsDelete(t *testing.T) {
	uploader := &fakeStorageOSSUploader{files: map[string]string{}}
	store := NewOSSStore(uploader, t.TempDir())
	ctx := context.Background()

	obj, err := store.Put(ctx, "reports/demo.txt", strings.NewReader("report"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if obj.Key != "reports/demo.txt" || obj.Backend != "oss" {
		t.Fatalf("unexpected object: %+v", obj)
	}
	if _, ok, err := store.Exists(ctx, "reports/demo.txt"); err != nil || !ok {
		t.Fatalf("Exists ok=%v err=%v", ok, err)
	}
	reader, opened, err := store.Open(ctx, "reports/demo.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if opened.Size != 6 || string(data) != "report" {
		t.Fatalf("unexpected opened=%+v data=%q", opened, string(data))
	}
	if err := store.Delete(ctx, "reports/demo.txt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if uploader.deletedKey != "reports/demo.txt" {
		t.Fatalf("deletedKey=%q", uploader.deletedKey)
	}
}
