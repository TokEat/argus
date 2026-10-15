package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlagWithErrorDoesNotCollideWithBinaryFile(t *testing.T) {
	// 在临时工作目录下模拟用户执行 ./arg 或 ./argus 的场景
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir tempDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	for _, binName := range []string{"argus", "arg"} {
		t.Run(binName, func(t *testing.T) {
			// 创建与工具同名的普通可执行文件（模拟二进制本体）
			binPath := filepath.Join(tempDir, binName)
			if err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatalf("create dummy binary %s: %v", binName, err)
			}
			defer os.Remove(binPath)

			origArgs := os.Args
			defer func() { os.Args = origArgs }()

			// 模拟以 ./<binName> 形式执行
			os.Args = []string{"./" + binName, "-a", "127.0.0.1", "-nopoc", "-nogpoc", "-nobr"}

			err := FlagWithError()
			if err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, "not a directory") {
					t.Fatalf("FlagWithError failed with directory collision: %v", err)
				}
				if strings.Contains(errMsg, "config.yaml") {
					t.Fatalf("FlagWithError failed with unexpected config.yaml error: %v", err)
				}
			}

			// 验证当前目录下绝未被创建名为 binName 的配置目录
			info, statErr := os.Stat(binPath)
			if statErr != nil {
				t.Fatalf("stat binary %s: %v", binName, statErr)
			}
			if info.IsDir() {
				t.Fatalf("expected %s to remain a regular file, but became directory", binName)
			}
		})
	}
}
