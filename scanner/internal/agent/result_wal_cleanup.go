package agent

import (
	"log"
	"os"
	"path/filepath"
	"time"
)

// orphanWALMaxAge 是 WAL 文件的最长残留时间：超过即视为历史崩溃残留并清理。
const orphanWALMaxAge = 24 * time.Hour

// cleanupOrphanWALs 清理 spoolDir 下残留过久（mtime 早于 orphanWALMaxAge）的 *.wal。
// 正常情况下 WAL 在任务尝试成功收敛后被 Discard 删除，残留文件来自 Agent 崩溃 / 被强杀。
// 短于阈值的文件保留——它们可能属于正在运行的任务，误删会导致断线后无法重放。
// best-effort：清理失败仅记日志，不影响启动。
func cleanupOrphanWALs(spoolDir string, now time.Time) {
	if spoolDir == "" {
		return
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		return
	}
	cutoff := now.Add(-orphanWALMaxAge)
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".wal" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(spoolDir, entry.Name())); err == nil {
			removed++
		}
	}
	if removed > 0 {
		log.Printf("[ResultWAL] cleaned %d orphaned wal file(s) older than %s in %s", removed, orphanWALMaxAge, spoolDir)
	}
}
