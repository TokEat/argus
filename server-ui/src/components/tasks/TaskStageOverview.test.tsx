import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import TaskStageOverview from './TaskStageOverview';

const detail = {
    task: { status: 'COMPLETED', total_targets: 2, completed_targets: 2 },
    batches: [
        { id: 'asset', kind: 'asset_scan', target_count: 1, status: 'Done' },
        { id: 'risk', kind: 'risk_validation', target_count: 1, status: 'Done' },
    ],
    scan_policy: {
        schema_version: 'argus.scan-policy/v1', policy_hash: 'a'.repeat(64), plan_hash: 'b'.repeat(64),
        risk_status: 'skipped', credential_status: 'skipped', authorized_at: '2026-08-13T00:00:00Z',
        policy: {
            schema_version: 'argus.scan-policy/v1', preset: 'standard', port_profile: 'top-1000',
            scan_method: 'tcp', intensity: 'balanced', credentials: { pair_limit: 50000 },
            authorization: { validation_confirmed: true },
            capabilities: {
                subdomain_discovery: true, subdomain_bruteforce: false, allow_cdn_assets: false,
                allow_private_resolved_domains: false, host_binding: false, directory_probe: false,
                risk_validation: true, credential_validation: false,
            },
        },
    },
    stage_derivations: [{ stage: 'risk_validation', status: 'skipped', summary: JSON.stringify({ reason: 'no_approved_workflow_matches' }) }],
} as unknown as API.TaskDetailResponse;

describe('TaskStageOverview', () => {
    it('区分用户未启用和已启用但无 Workflow 命中', () => {
        render(<TaskStageOverview detail={detail} />);
        expect(screen.getAllByText('无已审核 Workflow 命中，已跳过')).toHaveLength(2);
        expect(screen.getAllByText('未启用')).toHaveLength(2);
        expect(screen.getByText('1/1 目标')).toBeInTheDocument();
    });
});
