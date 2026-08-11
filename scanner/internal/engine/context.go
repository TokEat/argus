// Package engine 扫描引擎内核，封装完整的扫描流水线和上下文管理。
package engine

import (
	"context"
	"embed"
	"fmt"
	"sync"

	"github.com/P0lar1ght/argus/scanner/internal/taskstore"
	"github.com/P0lar1ght/argus/scanner/structs"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

// ScanContext 替代所有 structs.GlobalXXX 全局变量。
// 每次扫描任务创建一个独立实例，实现多任务间的数据隔离。
//
// 迁移对照:
//
//	structs.GlobalConfig         → ctx.Config
//	structs.GlobalIPPortMap      → ctx.IPPortMap
//	structs.GlobalIPDomainMap    → ctx.IPDomainMap
//	structs.GlobalURLMap         → ctx.URLMap
//	httpx.GlobalUsedUrl          → ctx.httpURLVisits（仅通过 TryVisitHTTPURL 访问）
//	structs.GlobalResultMap      → ctx.ResultMap
//	structs.DirFallbackResultMap → ctx.DirFallbackResultMap
//	structs.GoPocsResults        → ctx.GoPocsResults
//	structs.GlobalBannerHMap     → ctx.BannerHMap
//	structs.GlobalHttpBodyHMap   → ctx.BodyHMap
//	structs.GlobalHttpHeaderHMap → ctx.HeaderHMap
//	structs.GlobalEmbedPocs      → ctx.EmbedPocs
//	structs.FingerprintDB        → ctx.FingerprintDB
//	structs.WorkFlowDB           → ctx.WorkFlowDB
//	structs.DirDB                → ctx.DirDB
//	structs.AddScanNum           → ctx.AddScanNum
//	structs.AddScanEnd           → ctx.AddScanEnd
type ScanContext struct {
	// TaskID 任务唯一标识（分布式模式下由 Server 分配，单机模式自动生成）
	TaskID string

	// Config 扫描配置（从 CLI 参数或 Server 下发的任务中获取）
	Config Config

	// ResumePlan is an internal, Server-issued execution suffix. CLI scans
	// leave it nil and continue to execute the complete local pipeline.
	ResumePlan *scanplan.ResumePlan

	// LocalDataRoot is set only for standalone CLI scans. It points to the
	// compatibility root used by explicit offline arsenal commands and is never
	// uploaded.
	LocalDataRoot string
	LocalRunID    string
	// LocalForceFullScan is set only by the standalone CLI -force flag. It
	// bypasses local coverage reuse without changing scan scope or POC policy.
	LocalForceFullScan bool
	// LocalArsenalVersion is the validated semantic identity of the offline
	// arsenal.db package. It is empty when a source build falls back to embeds.
	LocalArsenalVersion string

	// --- 数据容器（替代 structs 包的全局 Map） ---

	// IPPortMap IP:Port → Protocol (如 "192.168.1.1:80" → "http")
	IPPortMap     map[string]string
	IPPortMapLock sync.Mutex

	// IPDomainMap 存储 IP → []Domain 的映射关系
	IPDomainMap     map[string][]string
	IPDomainMapLock sync.Mutex

	// URLMap RootURL → URLEntity (如 "http://example.com" → URLEntity{...})
	URLMap     map[string]URLEntity
	URLMapLock sync.Mutex

	// httpURLVisits records URLs submitted to the HTTP probe for this scan.
	// It is separate from URLMap, which stores probe results.
	httpURLVisits     map[string]struct{}
	httpURLVisitsLock sync.Mutex

	// ResultMap Target → []Fingerprint (指纹识别结果)
	ResultMap map[string][]string

	// DirFallbackResultMap 存储 dir-fallback 标记的指纹
	// 在 FingerprintIdentification 之后合并到 ResultMap
	DirFallbackResultMap     map[string][]string
	DirFallbackResultMapLock sync.Mutex

	// GoPocsResults 存储 Go Poc 的检测结果
	GoPocsResults []GoPocsResultType

	// --- 高性能缓存 (HybridMap 基于 LevelDB) ---

	// BannerHMap 协议 Banner 缓存
	BannerHMap *hybrid.HybridMap

	// BodyHMap HTTP 响应体缓存 (key=md5, value=body)
	BodyHMap *hybrid.HybridMap

	// HeaderHMap HTTP 响应头缓存 (key=md5, value=header)
	HeaderHMap *hybrid.HybridMap

	// --- 知识库（从 embed 或外部文件加载） ---

	// EmbedPocs 嵌入的 Nuclei PoC 文件系统
	EmbedPocs embed.FS

	// FingerprintDB 指纹规则数据库
	FingerprintDB []FingerPEntity

	// WorkFlowDB 指纹→PoC 工作流映射
	WorkFlowDB map[string]WorkFlowEntity

	// DirDB 主动指纹探测路径数据库
	DirDB map[string][]string

	// knowledge is an immutable, process-shared rules snapshot when the Agent
	// supplied a verified package identity. Pipeline readers use it instead of
	// the public compatibility fields above.
	knowledge *knowledgeSnapshot

	// --- 扫描计数器 ---

	// AddScanNum 额外扫描任务数（由搜索引擎等动态添加）
	AddScanNum int

	// AddScanEnd 额外扫描任务完成数
	AddScanEnd int

	// --- 输出 Hook ---

	// OutputHook 输出回调。CLI 模式下为文件写入，Agent 模式下为 gRPC 流式回传。
	// 如果为 nil，则使用默认的本地文件输出。
	OutputHook func(msg OutputMessage)

	// OutputObserver mirrors output without replacing the normal CLI file or
	// Agent stream sink. CLI history uses it so observation cannot accidentally
	// switch the Pipeline into Agent behavior.
	OutputObserver func(msg OutputMessage)

	// PhaseHook 阶段进度回调。Pipeline 每进入一个扫描阶段时触发。
	// 用于实时向 Server 推送扫描进度，让 UI 显示当前扫描所处阶段。
	// 如果为 nil，则不上报阶段进度。
	PhaseHook func(phase PhaseEvent)

	// PhaseObserver mirrors phase progress without replacing the Agent progress
	// sink. Standalone CLI history uses it to derive local coverage evidence.
	PhaseObserver func(phase PhaseEvent)

	// --- 生命周期 ---

	// Ctx 用于取消正在运行的扫描
	Ctx    context.Context
	Cancel context.CancelFunc
}

// NewScanContext 创建一个新的扫描上下文，初始化所有数据容器。
func NewScanContext(cfg Config) (*ScanContext, error) {
	ApplyConfigDefaults(&cfg)
	if err := ValidateLegacyProviderConfig(cfg); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	stores, err := taskstore.New(structs.Config(cfg))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initialize response stores: %w", err)
	}

	sc := &ScanContext{
		Config: cfg,

		IPPortMap:            make(map[string]string),
		IPDomainMap:          make(map[string][]string),
		URLMap:               make(map[string]URLEntity),
		httpURLVisits:        make(map[string]struct{}),
		ResultMap:            make(map[string][]string),
		DirFallbackResultMap: make(map[string][]string),

		BannerHMap: stores.Banner,
		BodyHMap:   stores.Body,
		HeaderHMap: stores.Header,

		EmbedPocs: structs.GlobalEmbedPocs,

		Ctx:    ctx,
		Cancel: cancel,
	}

	if err := sc.loadKnowledgeBase(); err != nil {
		sc.Close()
		return nil, err
	}

	return sc, nil
}

// TryVisitHTTPURL atomically records raw as submitted to the HTTP probe.
// It returns true only for the first visit during this ScanContext lifecycle.
// Callers that need URL normalization must do so before calling this method.
func (sc *ScanContext) TryVisitHTTPURL(raw string) bool {
	if sc == nil || raw == "" {
		return false
	}
	sc.httpURLVisitsLock.Lock()
	defer sc.httpURLVisitsLock.Unlock()
	if sc.httpURLVisits == nil {
		sc.httpURLVisits = make(map[string]struct{})
	}
	if _, visited := sc.httpURLVisits[raw]; visited {
		return false
	}
	sc.httpURLVisits[raw] = struct{}{}
	return true
}

// Reset 重置一个已结束执行分组的运行时数据，保留配置和知识库。
// 调用方必须保证没有活跃 Pipeline；CLI Planner 用它隔离连续执行分组。
func (sc *ScanContext) Reset() {
	sc.ResumePlan = nil
	sc.LocalRunID = ""
	sc.OutputObserver = nil
	sc.PhaseObserver = nil
	sc.IPPortMapLock.Lock()
	sc.IPPortMap = make(map[string]string)
	sc.IPPortMapLock.Unlock()

	sc.IPDomainMapLock.Lock()
	sc.IPDomainMap = make(map[string][]string)
	sc.IPDomainMapLock.Unlock()

	sc.URLMapLock.Lock()
	sc.URLMap = make(map[string]URLEntity)
	sc.URLMapLock.Unlock()

	sc.httpURLVisitsLock.Lock()
	sc.httpURLVisits = make(map[string]struct{})
	sc.httpURLVisitsLock.Unlock()

	sc.DirFallbackResultMapLock.Lock()
	sc.DirFallbackResultMap = make(map[string][]string)
	sc.DirFallbackResultMapLock.Unlock()

	sc.ResultMap = make(map[string][]string)
	sc.GoPocsResults = nil
	sc.AddScanNum = 0
	sc.AddScanEnd = 0
}

// DetachKnowledge makes the current rules independently writable for debug or
// custom-rule callers. Normal scan execution must not mutate shared rules.
func (sc *ScanContext) DetachKnowledge() {
	if sc == nil {
		return
	}
	if sc.knowledge != nil {
		sc.FingerprintDB = cloneFingerDB(sc.knowledge.fingerprintDB)
		sc.WorkFlowDB = cloneWorkflowDB(sc.knowledge.workflowDB)
		sc.DirDB = cloneDirDB(sc.knowledge.dirDB)
		sc.knowledge = nil
		return
	}
	sc.FingerprintDB = cloneFingerDB(sc.FingerprintDB)
	sc.WorkFlowDB = cloneWorkflowDB(sc.WorkFlowDB)
	sc.DirDB = cloneDirDB(sc.DirDB)
}

// Close 释放扫描上下文持有的所有资源。
func (sc *ScanContext) Close() {
	if sc.Cancel != nil {
		sc.Cancel()
	}
	if sc.BodyHMap != nil {
		sc.BodyHMap.Close()
	}
	if sc.HeaderHMap != nil {
		sc.HeaderHMap.Close()
	}
	if sc.BannerHMap != nil {
		sc.BannerHMap.Close()
	}
}
