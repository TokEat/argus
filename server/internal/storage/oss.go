package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/cloud"
)

type OSSStore struct {
	uploader cloud.OSSUploader
	tmpDir   string
}

func NewOSSStore(uploader cloud.OSSUploader, tmpDir string) *OSSStore {
	tmpDir = strings.TrimSpace(tmpDir)
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	return &OSSStore{uploader: uploader, tmpDir: tmpDir}
}

func (s *OSSStore) Put(ctx context.Context, key string, r io.Reader) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return Object{}, err
	}
	if err := os.MkdirAll(s.tmpDir, 0o755); err != nil {
		return Object{}, err
	}
	tmp, err := os.CreateTemp(s.tmpDir, "argus-oss-put-*")
	if err != nil {
		return Object{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	size, copyErr := io.Copy(tmp, r)
	closeErr := tmp.Close()
	if copyErr != nil {
		return Object{}, copyErr
	}
	if closeErr != nil {
		return Object{}, closeErr
	}
	if err := s.uploader.UploadFile(tmpPath, cleanKey); err != nil {
		return Object{}, err
	}
	return Object{Key: cleanKey, Size: size, ModTime: time.Now(), Backend: "oss"}, nil
}

func (s *OSSStore) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, Object{}, err
	}
	obj, ok, err := s.Exists(ctx, key)
	if err != nil {
		return nil, Object{}, err
	}
	if !ok {
		return nil, Object{}, os.ErrNotExist
	}
	if err := os.MkdirAll(s.tmpDir, 0o755); err != nil {
		return nil, Object{}, err
	}
	tmp, err := os.CreateTemp(s.tmpDir, "argus-oss-open-*")
	if err != nil {
		return nil, Object{}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	if err := s.uploader.DownloadFile(obj.Key, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, Object{}, err
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, Object{}, err
	}
	return removeOnClose{ReadCloser: f, path: tmpPath}, obj, nil
}

func (s *OSSStore) List(ctx context.Context, prefix string) ([]Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanPrefix, err := cleanObjectKey(prefix, true)
	if err != nil {
		return nil, err
	}
	files, err := s.uploader.ListFiles(cleanPrefix)
	if err != nil {
		return nil, err
	}
	objects := make([]Object, 0, len(files))
	for _, file := range files {
		objects = append(objects, Object{
			Key:     file.Key,
			Size:    file.Size,
			ModTime: file.LastModified,
			Backend: "oss",
		})
	}
	return objects, nil
}

func (s *OSSStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return err
	}
	return s.uploader.DeleteFile(cleanKey)
}

func (s *OSSStore) Exists(ctx context.Context, key string) (Object, bool, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, false, err
	}
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return Object{}, false, err
	}
	objects, err := s.List(ctx, filepath.ToSlash(filepath.Dir(cleanKey)))
	if err != nil {
		return Object{}, false, err
	}
	for _, obj := range objects {
		if obj.Key == cleanKey {
			return obj, true, nil
		}
	}
	return Object{}, false, nil
}

type removeOnClose struct {
	io.ReadCloser
	path string
}

func (r removeOnClose) Close() error {
	err := r.ReadCloser.Close()
	_ = os.Remove(r.path)
	return err
}
