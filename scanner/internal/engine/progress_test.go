package engine

import (
	"sync"
	"testing"
	"time"
)

func TestProgressWindow(t *testing.T) {
	if got := progressWindow(0); got != 1 {
		t.Errorf("progressWindow(0) = %d, want 1", got)
	}
	if got := progressWindow(-5); got != 1 {
		t.Errorf("progressWindow(-5) = %d, want 1", got)
	}
	if got := progressWindow(50); got != 1 {
		t.Errorf("progressWindow(50) = %d, want 1", got)
	}
	if got := progressWindow(8000); got != 80 {
		t.Errorf("progressWindow(8000) = %d, want 80", got)
	}
}

func TestProgressReporterNilHook(t *testing.T) {
	var r *progressReporter
	// nil receiver 必须安全，CLI 路径（无 ProgressHook）依赖这一点。
	r.enterPhase("port_scan", 100, false)
	r.tick()
	r.unit(1)
	r.flush()
	r.emit()
	if newProgressReporter(&ScanContext{}) != nil {
		t.Error("newProgressReporter without ProgressHook should return nil")
	}
}

func TestProgressReporterEmitsPhaseAndThrottledActivity(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	r := newProgressReporter(ctx)

	r.enterPhase("port_scan", 1000, false) // 应立即上报一帧
	if len(events) != 1 {
		t.Fatalf("expected immediate frame on enterPhase, got %d", len(events))
	}
	if events[0].Phase != "port_scan" || events[0].Total != 1000 || events[0].Done != 0 {
		t.Errorf("unexpected enter frame: %+v", events[0])
	}
	if events[0].Unit {
		t.Errorf("discovery-mode enter frame should not be Unit: %+v", events[0])
	}

	// window = 1000/100 = 10；前 9 次活动不应上报，第 10 次应上报。
	for i := 0; i < 9; i++ {
		r.tick()
	}
	if len(events) != 1 {
		t.Fatalf("expected throttle before window, got %d frames", len(events))
	}
	// 绕过最小间隔节流，直接验证窗口语义。
	r.mu.Lock()
	r.lastEmit = time.Now().Add(-time.Second)
	r.mu.Unlock()
	r.tick()
	if len(events) != 2 {
		t.Fatalf("expected frame at window boundary, got %d", len(events))
	}
	if events[1].Done != 10 || events[1].Total != 1000 {
		t.Errorf("unexpected activity frame: %+v", events[1])
	}
}

func TestProgressReporterFlushEmitsPending(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	r := newProgressReporter(ctx)
	r.enterPhase("protocol_identify", 500, false)
	r.tick() // pending=1，未达窗口（500/100=5），被抑制
	r.tick()
	r.flush()
	if len(events) != 2 {
		t.Fatalf("expected enter + flush frames, got %d", len(events))
	}
	if events[1].Done != 2 || events[1].Phase != "protocol_identify" {
		t.Errorf("unexpected flush frame: %+v", events[1])
	}
}

func TestEmitPhaseDrivesDiscoveryProgress(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	ctx.progress = newProgressReporter(ctx)
	// 发现模式：emitPhase 不携带总量，进度仅「有活动」。
	emitPhase(ctx, PhasePortScan, "start", "8000 ips, type=tcp")
	if len(events) != 1 || events[0].Total != 0 || events[0].Unit {
		t.Fatalf("emitPhase start should drive discovery progress with unknown total, got %+v", events)
	}
	emitPhase(ctx, PhasePortScan, "end", "120 tcp, 3 udp")
	if len(events) != 1 {
		t.Fatalf("emitPhase end without activity should not add frame, got %d", len(events))
	}
	ctx.progress.tick()
	emitPhase(ctx, PhasePortScan, "end", "done")
	if len(events) != 2 || events[1].Done != 1 {
		t.Fatalf("emitPhase end should flush pending activity, got %+v", events)
	}
}

func TestProgressReporterUnitModeComputesRateAndEta(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	r := newProgressReporter(ctx)

	const total = 1000
	r.enterPhase("port_scan", total, true)
	if len(events) != 1 {
		t.Fatalf("enter should emit immediately, got %d", len(events))
	}
	if !events[0].Unit {
		t.Fatalf("unit-mode enter frame should be Unit: %+v", events[0])
	}
	// 单元模式下 tick（发现计数）必须被忽略，避免双计。
	r.tick()
	r.tick()
	r.tick()
	if len(events) != 1 {
		t.Fatalf("discovery tick must be no-op in unit mode, got %d frames", len(events))
	}
	// 推进 250 个单元后强制一帧（绕过最小间隔）。
	for i := 0; i < 250; i++ {
		r.unit(1)
	}
	r.mu.Lock()
	r.lastEmit = time.Now().Add(-time.Second)
	r.mu.Unlock()
	r.unit(1)
	if len(events) != 2 {
		t.Fatalf("expected unit frame, got %d", len(events))
	}
	last := events[1]
	if !last.Unit || last.Done != 251 || last.Total != total {
		t.Fatalf("unit frame wrong: %+v", last)
	}
	if last.Rate <= 0 {
		t.Fatalf("unit frame should carry positive rate: %+v", last)
	}
	if last.EtaMillis < 0 {
		t.Fatalf("eta must not be negative: %+v", last)
	}
	// 推进到完成：remaining=0 → ETA 归零，done==total。
	for i := 0; i < total-251; i++ {
		r.unit(1)
	}
	r.flush()
	final := events[len(events)-1]
	if final.Done != total || final.Total != total {
		t.Fatalf("unit mode should converge done==total, got %+v", final)
	}
	if final.EtaMillis != 0 {
		t.Fatalf("eta should be 0 when complete, got %+v", final)
	}
}

func TestProgressReporterUnitModeIsNoOpInDiscoveryMode(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	r := newProgressReporter(ctx)
	r.enterPhase("http_probe", 0, false)
	// 发现模式下 unit() 必须被忽略，避免双计。
	r.unit(5)
	r.mu.Lock()
	r.lastEmit = time.Now().Add(-time.Second)
	r.mu.Unlock()
	r.unit(5)
	if len(events) != 1 {
		t.Fatalf("unit must be no-op in discovery mode, got %d frames", len(events))
	}
	// total=0 → window=1，单次发现活动即达窗口应上报；Done 只算 tick 的 1，
	// 不含前面被忽略的 unit(5)，证明两种模式互不双计。
	r.tick()
	if len(events) != 2 || events[1].Done != 1 {
		t.Fatalf("discovery tick should emit once with done=1 (unit excluded), got %+v", events)
	}
}

func TestProgressReporterConcurrentTickAndUnit(t *testing.T) {
	var events []ProgressEvent
	ctx := &ScanContext{ProgressHook: func(event ProgressEvent) { events = append(events, event) }}
	r := newProgressReporter(ctx)
	r.enterPhase("port_scan", 10000, true)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.unit(1)
				r.tick() // 单元模式下应为 no-op
			}
		}()
	}
	wg.Wait()
	r.flush()

	// done 必须精确等于 8×500=4000（并发不丢/不重），且无数据竞争（-race）。
	if got := r.doneCount(); got != 4000 {
		t.Fatalf("concurrent unit count = %d, want 4000", got)
	}
}

func (r *progressReporter) doneCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done
}
