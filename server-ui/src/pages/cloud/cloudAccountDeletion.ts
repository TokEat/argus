import { APIRequestError } from '../../services/request';

export const getCloudAccountPolicyConflict = (error: unknown, accountId: string): API.CloudAccountPolicyConflict | null => {
    if (!(error instanceof APIRequestError) || !error.responseData || typeof error.responseData !== 'object') return null;
    const data = error.responseData as Partial<API.CloudAccountPolicyConflict>;
    if (data.code !== 'cloud_account_has_policies' || data.cloud_account_id !== accountId
        || !Number.isSafeInteger(data.policy_count) || (data.policy_count ?? 0) < 1
        || typeof data.policies_truncated !== 'boolean' || !Array.isArray(data.policies)
        || data.policies.length > 20 || data.policies.length > (data.policy_count ?? 0)) return null;
    if (!data.policies.every(policy => policy && typeof policy.id === 'string' && policy.id !== ''
        && typeof policy.name === 'string' && typeof policy.enabled === 'boolean')) return null;
    return data as API.CloudAccountPolicyConflict;
};
