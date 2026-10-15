import { describe, expect, it } from 'vitest';
import { COVERAGE_GAP_STATUS_LABELS, coverageReasonText, scanStageLabel } from './taskCoverageReasons';

describe('taskCoverageReasons', () => {
    it('translates compound risk coverage codes into Chinese', () => {
        expect(coverageReasonText('poc_set_unknown,endpoint_content_unknown')).toBe(
            '风险验证已完成，但未记录可复用的 POC 集合；风险验证已完成，但未绑定该目标的 HTTP 探测内容版本，下次不能复用',
        );
    });

    it('translates skipped and HTTP budget failures', () => {
        expect(coverageReasonText('stage_not_executed')).toBe('该阶段对本批次不适用或已按策略跳过');
        expect(coverageReasonText('http_budget_exhausted')).toBe('HTTP 探测超时，未得到完整响应');
        expect(coverageReasonText('upstream_http_probe_incomplete')).toBe(
            '上游 HTTP 探测未完成，后续指纹与目录未形成可复用覆盖',
        );
        expect(coverageReasonText('nuclei_execution_failed')).toBe('Nuclei 执行失败');
        expect(coverageReasonText('fingerprint_unmatched_pocs')).toBe('指纹未匹配到可执行 POC');
    });

    it('labels reuse-only risk coverage as not reusable instead of failed', () => {
        expect(COVERAGE_GAP_STATUS_LABELS.not_reusable.label).toBe('不可复用');
        expect(COVERAGE_GAP_STATUS_LABELS.invalidated.label).toBe('已失效');
    });

    it('keeps upstream content change stage names in Chinese', () => {
        expect(coverageReasonText('upstream_content_changed:http_probe')).toBe('上游内容变化（HTTP 探测）');
        expect(scanStageLabel('protocol_identification')).toBe('协议识别');
    });
});
