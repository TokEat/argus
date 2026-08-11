import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from 'antd';
import TaskTimingPanel from './TaskTimingPanel';

const stageLabels = { port_scan: '端口扫描' };

describe('TaskTimingPanel', () => {
    it('shows preparation and stage events', () => {
        render(
            <App>
                <TaskTimingPanel
                    stageLabels={stageLabels}
                    timing={{
                        truncated: false,
                        attempts: [{
                            attempt_id: 'attempt-timing-1',
                            available: true,
                            events: [
                                { kind: 'rule_prepare', outcome: 'success', duration_ms: 12, started_at: '2026-08-10T01:00:00Z', finished_at: '2026-08-10T01:00:01Z' },
                                { kind: 'stage', stage: 'port_scan', outcome: 'negative', duration_ms: 35, started_at: '2026-08-10T01:00:01Z', finished_at: '2026-08-10T01:00:02Z' },
                            ],
                        }],
                    }}
                />
            </App>,
        );

        expect(screen.getByText('执行阶段计时 (1)')).toBeInTheDocument();
        expect(screen.getByText('规则准备')).toBeInTheDocument();
        expect(screen.getByText('阶段：端口扫描')).toBeInTheDocument();
        expect(screen.getByText('阶段耗时由 Agent 进程内计时；各阶段合计可能与尝试的墙钟时间不同。')).toBeInTheDocument();
    });

    it('labels timing as unavailable for an old Agent instead of showing zero duration', () => {
        render(
            <App>
                <TaskTimingPanel
                    stageLabels={stageLabels}
                    timing={{ truncated: false, attempts: [{ attempt_id: 'attempt-old-1', available: false }] }}
                />
            </App>,
        );

        expect(screen.getByText('旧版 Agent 暂无阶段计时')).toBeInTheDocument();
        expect(screen.queryByText('0 ms')).not.toBeInTheDocument();
    });

    it('renders sub-millisecond timing and warns when timing events are truncated', () => {
        render(
            <App>
                <TaskTimingPanel
                    stageLabels={stageLabels}
                    timing={{
                        truncated: true,
                        attempts: [{
                            attempt_id: 'attempt-short-1',
                            available: true,
                            events: [{ kind: 'context_init', outcome: 'success', duration_ms: 0, duration_ns: 750_000 }],
                        }],
                    }}
                />
            </App>,
        );

        expect(screen.getByText('<1 ms')).toBeInTheDocument();
        expect(screen.getByText('计时记录已截断，仅显示可返回的部分事件。')).toBeInTheDocument();
    });
});
