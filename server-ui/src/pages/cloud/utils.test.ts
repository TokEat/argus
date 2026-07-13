import { describe, expect, it } from 'vitest';
import { buildDefaultPolicyFormValues, buildPolicyFormValues, DEFAULT_CLOUD_INIT_TEMPLATE, extractErrorMsg } from './utils';

describe('cloud utilities', () => {
    it('normalizes the error shapes used by API and form handlers', () => {
        expect(extractErrorMsg('plain failure')).toBe('plain failure');
        expect(extractErrorMsg(new Error('network failure'))).toBe('network failure');
        expect(extractErrorMsg({ error: 'provider failure' })).toBe('provider failure');
        expect(extractErrorMsg({ message: 'request failure' })).toBe('request failure');
        expect(extractErrorMsg({ errorFields: [{ name: ['account_id'] }] })).toBeNull();
    });

    it('keeps the server-rendered placeholders in the default Cloud-Init template', () => {
        expect(DEFAULT_CLOUD_INIT_TEMPLATE).toContain('{{.DownloadURL}}');
        expect(DEFAULT_CLOUD_INIT_TEMPLATE).toContain('{{.ServerAddr}}');
        expect(DEFAULT_CLOUD_INIT_TEMPLATE).toContain('{{.AgentID}}');
        expect(DEFAULT_CLOUD_INIT_TEMPLATE).toContain('{{.PSK}}');
    });

    it('builds stable policy form defaults without losing explicit zero values', () => {
        const defaults = buildDefaultPolicyFormValues([{ id: 'account-1' } as API.CloudAccount]);
        expect(defaults.cloud_account_id).toBe('account-1');
        expect(buildPolicyFormValues(defaults, {
            id: 'policy-1',
            min_instances: 0,
            scale_down_threshold: 0,
        } as API.CloudScalingPolicy)).toMatchObject({
            min_instances: 0,
            scale_down_threshold: 0,
        });
    });
});
