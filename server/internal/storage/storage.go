package storage

import (
	"context"
	"io"
	"time"
)

type Object struct {
	Key     string
	Size    int64
	ModTime time.Time
	Backend string
}

type Store interface {
	Put(ctx context.Context, key string, r io.Reader) (Object, error)
	Open(ctx context.Context, key string) (io.ReadCloser, Object, error)
	List(ctx context.Context, prefix string) ([]Object, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (Object, bool, error)
}
