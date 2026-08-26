export const SCAN_STAGE_LABELS: Record<string, string> = {
    search_engine: '空间搜索',
    subdomain_discovery: '子域发现',
    cdn_classification: 'CDN 识别',
    icmp_discovery: 'ICMP 存活',
    tcp_liveness: 'TCP 存活',
    port_scan: '端口扫描',
    protocol_identify: '协议识别',
    protocol_identification: '协议识别',
    http_probe: 'HTTP 探测',
    host_binding: 'Host 绑定',
    behavior_probe: '安全行为探针',
    directory_probe: '主动路径指纹',
    fingerprint: '指纹识别',
    risk_validation: '风险验证',
};

export const COVERAGE_REASON_LABELS: Record<string, string> = {
    valid_project_coverage: '同项目有效历史覆盖',
    checkpoint_resume: '有效检查点恢复',
    claimed_for_execution: '当前尝试领取执行',
    active_work_claim: '相同工作正在其他尝试执行',
    source_replanned: '来源尝试已重新规划',
    source_failed: '来源尝试失败，等待重新规划',
    ttl_expired: '覆盖已超过有效期',
    agent_config_hash_mismatch: 'Agent 配置证据不一致',
    rule_version_mismatch: '规则版本不一致',
    rule_version_mismatch_or_unknown: '规则版本不一致或未知',
    project_scope_invalid: '项目范围无效，覆盖不可复用',
    poc_set_unknown: '风险验证已完成，但未记录可复用的 POC 集合',
    endpoint_content_unknown: '风险验证已完成，但未绑定该目标的 HTTP 探测内容版本，下次不能复用',
    fingerprint_unmatched_pocs: '指纹未匹配到可执行 POC',
    stage_not_executed: '该阶段对本批次不适用或已按策略跳过',
    phase_skipped: '该阶段被跳过',
    phase_failed: '阶段执行失败',
    phase_incomplete: '阶段已开始但没有正常结束',
    pipeline_cancelled: '任务取消，阶段未完成',
    pipeline_failed: '流水线失败，阶段未完成',
    http_budget_exhausted: '该目标 HTTP 探测耗尽网络预算，未得到完整响应',
    upstream_http_probe_incomplete: '上游 HTTP 探测未完成，后续指纹与目录未形成可复用覆盖',
    nuclei_execution_failed: 'Nuclei 执行失败',
    coverage_invalidated: '覆盖已失效，不可作为历史复用',
};

export const COVERAGE_GAP_STATUS_LABELS: Record<string, { label: string; color: string }> = {
    skipped: { label: '已跳过', color: 'default' },
    failed: { label: '阶段失败', color: 'volcano' },
    invalidated: { label: '已失效', color: 'red' },
    expired: { label: '已过期', color: 'orange' },
    incomplete: { label: '未完成', color: 'orange' },
};

export function scanStageLabel(stage: string): string {
    return SCAN_STAGE_LABELS[stage] || stage || '-';
}

export function coverageReasonText(reason: string): string {
    const value = (reason || '').trim();
    if (!value) return '-';
    const parts = value.split(',').map((part) => part.trim()).filter(Boolean);
    if (parts.length > 1) {
        return parts.map((part) => coverageReasonText(part)).join('；');
    }
    if (COVERAGE_REASON_LABELS[value]) {
        return COVERAGE_REASON_LABELS[value];
    }
    if (value.startsWith('upstream_content_changed:')) {
        const stage = value.slice('upstream_content_changed:'.length);
        return `上游内容变化（${scanStageLabel(stage)}）`;
    }
    return value;
}
