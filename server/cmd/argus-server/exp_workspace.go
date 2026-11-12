package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/expworkspace"
	"github.com/TokEat/argus/server/internal/storage"
	"gorm.io/gorm"
)

func initializeEXPWorkspace(ctx context.Context, database *gorm.DB, devMode bool) (*expworkspace.Service, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_EXP_STORE_MODE")))
	if mode == "" {
		if devMode {
			mode = "local"
		} else {
			mode = "minio"
		}
	}

	var objects storage.Store
	switch mode {
	case "minio":
		useSSL, err := strconv.ParseBool(defaultString(os.Getenv("ARGUS_EXP_MINIO_USE_SSL"), "false"))
		if err != nil {
			return nil, errors.New("ARGUS_EXP_MINIO_USE_SSL must be true or false")
		}
		objects, err = storage.NewS3Store(ctx, storage.S3Config{
			Endpoint:  os.Getenv("ARGUS_EXP_MINIO_ENDPOINT"),
			Region:    defaultString(os.Getenv("ARGUS_EXP_MINIO_REGION"), "us-east-1"),
			Bucket:    os.Getenv("ARGUS_EXP_MINIO_BUCKET"),
			AccessKey: os.Getenv("ARGUS_EXP_MINIO_ACCESS_KEY"),
			SecretKey: os.Getenv("ARGUS_EXP_MINIO_SECRET_KEY"),
			UseSSL:    useSSL,
		})
		if err != nil {
			return nil, err
		}
	case "local":
		if !devMode {
			return nil, errors.New("ARGUS_EXP_STORE_MODE=local is only allowed with --dev")
		}
		var err error
		objects, err = storage.NewLocalStore(defaultString(os.Getenv("ARGUS_EXP_LOCAL_ROOT"), "./data/exp-objects"))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported ARGUS_EXP_STORE_MODE %q", mode)
	}

	runtimeURL := defaultString(os.Getenv("ARGUS_YAKSHA_URL"), "http://127.0.0.1:8790")
	runtime, err := expworkspace.NewRuntimeClient(runtimeURL)
	if err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	readyErr := runtime.Ready(readyCtx)
	cancel()
	if readyErr != nil && !devMode {
		return nil, readyErr
	}
	retention := 7 * 24 * time.Hour
	if raw := strings.TrimSpace(os.Getenv("ARGUS_EXP_TRACE_RETENTION")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed <= 0 {
			return nil, errors.New("ARGUS_EXP_TRACE_RETENTION must be a positive duration")
		}
		retention = parsed
	}
	return expworkspace.NewService(database, objects, runtime, retention)
}

func seedDevelopmentEXPWorkspace(ctx context.Context, service *expworkspace.Service, devMode bool) ([]expworkspace.LabSeedResult, error) {
	raw := strings.TrimSpace(os.Getenv("ARGUS_EXP_LAB_SEED"))
	if raw == "" {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, errors.New("ARGUS_EXP_LAB_SEED must be true or false")
	}
	if !enabled {
		return nil, nil
	}
	if !devMode {
		return nil, errors.New("ARGUS_EXP_LAB_SEED is only allowed with --dev")
	}
	return service.SeedDevelopmentLab(ctx, defaultString(os.Getenv("ARGUS_EXP_LAB_TENANT"), "default"), "argus-exp-lab-seed")
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
