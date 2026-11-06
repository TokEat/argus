package scanplan

// ProgressEventPayloadType 标识 Agent 流中的细粒度进度帧。与 phase（仅阶段边界、
// broadcast-only 不入库）不同，progress 帧携带当前阶段 + 活动计数 + 输入总数，
// server 据此刷新 sub_tasks.progress_* 让进度条在大批次内持续推进。帧为尽力而为：
// 服务端解析或归属校验失败时静默丢弃，绝不影响结果流。
const ProgressEventPayloadType = "scan_progress"

// ProgressEvent 是 Agent → Server 的细粒度进度帧载荷。
//
// 两种计数模式（由 Agent 引擎按阶段声明，Server/UI 据此区分渲染）：
//   - 发现模式（unit=false，omitted）：Done 是当前阶段内的活动计数（发现类输出数），
//     Total 是该阶段输入总数，二者单位不同，Done 仅作「仍在推进」的实时信号，
//     不作为完成度占比；Rate/EtaMillis 为 0（omitted）。
//   - 单元模式（unit=true）：Done 与 Total 同口径（如端口扫描 connect 尝试数 = ips×ports），
//     可显示 done/total 占比；Rate 为吞吐（单元/秒），EtaMillis 为预计剩余毫秒。
//
// 旧 Agent 帧不含新字段（零值），Server 解析后按发现模式处理，向后兼容。
type ProgressEvent struct {
	Phase     string  `json:"phase"`
	Done      int     `json:"done"`
	Total     int     `json:"total"`
	Unit      bool    `json:"unit,omitempty"`
	Rate      float64 `json:"rate,omitempty"`
	EtaMillis int64   `json:"eta_ms,omitempty"`
}
