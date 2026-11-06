package engine

import (
	"sync"
	"time"
)

// progressReporter 聚合细粒度进度：跟踪当前阶段 + 该阶段输入总数 + 活动计数，
// 并按节流窗口把 ProgressEvent 推给 ctx.ProgressHook。它在 Pipeline.Run 期间随
// emit 收口点（每次发现类输出）与 emitPhase（阶段边界）驱动，让 Agent 模式的
// server 进度条在大批次执行期间持续收到「当前阶段 + 仍在推进」的信号，而不是
// 卡在某个点。零值不可用，须用 newProgressReporter 构造；hook 为 nil 时返回 nil，
// 所有方法对 nil receiver 安全，便于在无 ProgressHook 的 CLI 路径上免判空调用。
//
// 两种计数模式（互斥，由 enterPhase 的 unitMode 决定，绝不双计）：
//   - 发现模式（unitMode=false）：done 由 tick() 累加，单位是「发现类输出数」，
//     与 total 单位不同，只作「仍在推进」信号，不显示占比/ETA。
//   - 单元模式（unitMode=true）：done 由 unit(n) 累加，单位与 total 一致（如端口
//     扫描的 connect 尝试数 = ips×ports），可显示 done/total 占比、吞吐与 ETA。
//
// 线程安全：emit/tick/unit 会被 portscan、identify 的多个工作 goroutine 并发调用，
// 内部以互斥锁串行化状态变更（此前无锁，存在数据竞争）；hook 在锁外触发，避免
// 网络发送阻塞反向拖住扫描工作线程。
type progressReporter struct {
	mu         sync.Mutex
	hook       func(ProgressEvent)
	phase      string
	total      int
	done       int
	window     int // 每上报一次所需的活动数；单元模式固定 1（靠最小间隔节流）
	pending    int // 自上次上报以来累计、未上报的活动数
	lastEmit   time.Time
	phaseStart time.Time // 进入当前阶段的时间，单元模式据此算吞吐/ETA
	unitMode   bool
}

// progressEmitMinInterval 是相邻两帧之间的最小间隔，防止发现密集阶段刷爆流。
const progressEmitMinInterval = 300 * time.Millisecond

func newProgressReporter(ctx *ScanContext) *progressReporter {
	if ctx == nil || ctx.ProgressHook == nil {
		return nil
	}
	return &progressReporter{hook: ctx.ProgressHook, window: 1}
}

// progressWindow 按输入总量推导节流窗口：约每阶段 100 帧；总量未知时每次活动都上报。
// 仅用于发现模式；单元模式用最小间隔节流，窗口固定 1（见 enterPhase）。
func progressWindow(total int) int {
	if total <= 0 {
		return 1
	}
	w := total / 100
	if w < 1 {
		return 1
	}
	return w
}

// enterPhase 在阶段开始时调用：记录阶段与输入总数、清零计数，并立即上报一帧
// 让进度条切换到新阶段。total 为该阶段已知的输入总数，未知传 0；unitMode 选择
// 单元计数（done/total 同口径，显示占比/ETA）还是发现计数（仅活跃信号）。
func (r *progressReporter) enterPhase(phase string, total int, unitMode bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.phase = phase
	r.total = total
	r.done = 0
	r.pending = 0
	r.unitMode = unitMode
	r.phaseStart = time.Now()
	r.lastEmit = r.phaseStart
	ev := r.frameLocked(r.phaseStart)
	hook := r.hook
	r.mu.Unlock()
	if hook != nil {
		hook(ev)
	}
}

// account 在单元/发现模式下累计 n 个活动，并判断是否到达节流窗口该上报一帧。
// unit 必须与当前模式一致，否则忽略（模式隔离，避免双计）。返回应上报的帧。
func (r *progressReporter) account(n int, unit bool) (ProgressEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hook == nil || r.unitMode != unit {
		return ProgressEvent{}, false
	}
	r.done += n
	r.pending += n
	if r.pending < r.window {
		return ProgressEvent{}, false
	}
	if time.Since(r.lastEmit) < progressEmitMinInterval {
		return ProgressEvent{}, false
	}
	r.pending = 0
	r.lastEmit = time.Now()
	return r.frameLocked(r.lastEmit), true
}

// frameLocked 构造当前帧；调用方须已持有 r.mu。单元模式且已有进度时计算吞吐与 ETA。
func (r *progressReporter) frameLocked(now time.Time) ProgressEvent {
	ev := ProgressEvent{Phase: r.phase, Done: r.done, Total: r.total, Unit: r.unitMode}
	if r.unitMode && r.done > 0 && r.total > 0 {
		if elapsed := now.Sub(r.phaseStart).Seconds(); elapsed > 0 {
			ev.Rate = float64(r.done) / elapsed
			if remaining := r.total - r.done; remaining > 0 {
				ev.EtaMillis = int64(float64(remaining) / ev.Rate * 1000)
			}
		}
	}
	return ev
}

// tick 在每次活动（emit 收口点的一次发现类输出）时调用，达到节流窗口才上报。
// 单元模式下为 no-op（由 unit 计数），避免同一阶段双计。
func (r *progressReporter) tick() {
	if r == nil {
		return
	}
	if ev, ok := r.account(1, false); ok {
		r.hook(ev)
	}
}

// unit 在单元模式下累计 n 个已处理单元（如一次 connect 尝试），达到节流窗口才上报。
// 发现模式下为 no-op（由 tick 计数）。
func (r *progressReporter) unit(n int) {
	if r == nil || n <= 0 {
		return
	}
	if ev, ok := r.account(n, true); ok {
		r.hook(ev)
	}
}

// flush 在活动计数越过窗口但受最小间隔抑制时，确保阶段切换前的最新计数仍被送出；
// 由 emitPhase 在阶段结束时调用。
func (r *progressReporter) flush() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.hook == nil || r.pending == 0 {
		r.mu.Unlock()
		return
	}
	r.pending = 0
	r.lastEmit = time.Now()
	ev := r.frameLocked(r.lastEmit)
	hook := r.hook
	r.mu.Unlock()
	hook(ev)
}

// emit 立即按当前状态上报一帧（供 enterPhase/测试等需要即时帧的场景）。
func (r *progressReporter) emit() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.hook == nil {
		r.mu.Unlock()
		return
	}
	r.lastEmit = time.Now()
	ev := r.frameLocked(r.lastEmit)
	hook := r.hook
	r.mu.Unlock()
	hook(ev)
}
