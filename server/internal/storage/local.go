package storage

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type LocalStore struct {
	root string
}

func NewLocalStore(root string) (*LocalStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("storage root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &LocalStore{root: abs}, nil
}

func (s *LocalStore) Put(ctx context.Context, key string, r io.Reader) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	fullPath, cleanKey, err := s.resolve(key)
	if err != nil {
		return Object{}, err
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return Object{}, err
	}
	tmpPath := fullPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return Object{}, err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return Object{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return Object{}, closeErr
	}
	if err := os.Rename(tmpPath, fullPath); err != nil {
		_ = os.Remove(tmpPath)
		return Object{}, err
	}
	return s.statObject(cleanKey, fullPath)
}

func (s *LocalStore) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, Object{}, err
	}
	fullPath, cleanKey, err := s.resolve(key)
	if err != nil {
		return nil, Object{}, err
	}
	obj, err := s.statObject(cleanKey, fullPath)
	if err != nil {
		return nil, Object{}, err
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, Object{}, err
	}
	return f, obj, nil
}

func (s *LocalStore) List(ctx context.Context, prefix string) ([]Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanPrefix, err := cleanObjectKey(prefix, true)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.root); errors.Is(err, os.ErrNotExist) {
		return []Object{}, nil
	} else if err != nil {
		return nil, err
	}

	objects := []Object{}
	err = filepath.WalkDir(s.root, func(fullPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.root, fullPath)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if cleanPrefix != "" && !strings.HasPrefix(key, cleanPrefix) {
			return nil
		}
		obj, err := s.statObject(key, fullPath)
		if err != nil {
			return err
		}
		objects = append(objects, obj)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})
	return objects, nil
}

func (s *LocalStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fullPath, _, err := s.resolve(key)
	if err != nil {
		return err
	}
	return os.Remove(fullPath)
}

func (s *LocalStore) Exists(ctx context.Context, key string) (Object, bool, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, false, err
	}
	fullPath, cleanKey, err := s.resolve(key)
	if err != nil {
		return Object{}, false, err
	}
	obj, err := s.statObject(cleanKey, fullPath)
	if errors.Is(err, os.ErrNotExist) {
		return Object{}, false, nil
	}
	if err != nil {
		return Object{}, false, err
	}
	return obj, true, nil
}

func (s *LocalStore) resolve(key string) (string, string, error) {
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return "", "", err
	}
	fullPath := filepath.Join(s.root, filepath.FromSlash(cleanKey))
	if !strings.HasPrefix(fullPath, s.root+string(os.PathSeparator)) && fullPath != s.root {
		return "", "", errors.New("object key escapes storage root")
	}
	return fullPath, cleanKey, nil
}

func (s *LocalStore) statObject(key, fullPath string) (Object, error) {
	info, err := os.Stat(fullPath)
	if err != nil {
		return Object{}, err
	}
	if info.IsDir() {
		return Object{}, errors.New("object key points to a directory")
	}
	return Object{Key: key, Size: info.Size(), ModTime: info.ModTime(), Backend: "local"}, nil
}

func cleanObjectKey(key string, allowEmpty bool) (string, error) {
	key = strings.TrimSpace(filepath.ToSlash(key))
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("object key is required")
	}
	clean := path.Clean(key)
	if clean == "." {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("object key is required")
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("object key escapes storage root")
	}
	return clean, nil
}
