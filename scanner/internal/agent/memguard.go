package agent

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/mem"
)

// 内存准入护栏：防止 agent 在宿主机内存紧张时继续领新任务 / 启动新扫描导致 OOM。
// 软限（默认 80%）：claimAvailableTasks 拒领新任务，任务留在队列稍后或其他 agent 执行；
// 硬限（默认 90%）：executeTask 启动前拒绝执行并上报失败（原因含 "agent memory pressure"），
// 由人工/后续重试，而不是硬撑到宿主机 OOM。与 Worker.sem 的 CPU 并发上限互补。
// 注意：gopsutil 的 UsedPercent 在 Linux 上为 (Total-Available)/Total，不含可回收
// page cache，适合作为 OOM 预测信号；阈值应高于宿主机常规水位校准。
type memGuard struct {
	softPct float64
	hardPct float64
	// read 返回当前内存使用百分比；可注入替身便于测试。
	read func() (float64, error)
}

func newMemGuard() *memGuard {
	return &memGuard{
		softPct: memEnvPct("ARGUS_MEM_SOFT_PCT", 80),
		hardPct: memEnvPct("ARGUS_MEM_HARD_PCT", 90),
		read: func() (float64, error) {
			v, err := mem.VirtualMemory()
			if err != nil {
				return 0, err
			}
			return v.UsedPercent, nil
		},
	}
}

func memEnvPct(key string, def float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 || v > 100 {
		log.Printf("[memguard] invalid %s=%q, fallback to %.0f", key, raw, def)
		return def
	}
	return v
}

func (g *memGuard) overSoft() bool { return g.over(g.softPct) }

func (g *memGuard) overHard() bool { return g.over(g.hardPct) }

// over 读取失败时不阻塞任务（宁可在读不到内存信息时放行，也不误判压死扫描）。
func (g *memGuard) over(pct float64) bool {
	used, err := g.read()
	if err != nil {
		log.Printf("[memguard] read memory stats failed: %v", err)
		return false
	}
	return used >= pct
}
