import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useCloudDiscovery } from './useCloudDiscovery';

const apiMocks = vi.hoisted(() => ({
    autoConfigureCloudAccount: vi.fn(),
    checkCloudPermissions: vi.fn(),
    discoverCloudResources: vi.fn(),
    listCloudRegions: vi.fn(),
    listCloudRecommendations: vi.fn(),
    oneClickSetup: vi.fn(),
    updateCloudAccountRegion: vi.fn(),
}));

vi.mock('../../services/api', () => apiMocks);

const account = { id: 'account-1', name: 'test', region: 'cn-hangzhou', access_level: 'owner' } as API.CloudAccount;
const recommendation = { region: 'cn-hangzhou', instance_type: 'ecs.e-c1m1.large', cpu: 2, memory_gb: 2, total_hourly: 0.05, currency: 'CNY', price_unit: 'Hour', price_source: 'spot' } as API.CloudRecommendationItem;
const recommendationFor = (region: string) => ({ ...recommendation, region, instance_type: `ecs.${region}` });
const discovery = (region: string) => ({
    region,
    instance_types: [{ id: `ecs.${region}`, cpu: 2, memory_gb: 2, family: 'ecs.e' }],
    images: [{ id: `image-${region}`, name: 'image', desc: '' }],
    security_groups: [{ id: `sg-${region}`, name: 'default' }],
    v_switches: [{ id: `vsw-${region}`, name: 'default' }],
});
const deferred = <T,>() => {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>(resolvePromise => { resolve = resolvePromise; });
    return { promise, resolve };
};

describe('useCloudDiscovery', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        apiMocks.listCloudRegions.mockResolvedValue({ regions: [] });
        apiMocks.autoConfigureCloudAccount.mockResolvedValue({ status: 'ok' });
    });

    it('clears stale regional recommendations when the new price query fails', async () => {
        apiMocks.discoverCloudResources
            .mockResolvedValueOnce(discovery('cn-hangzhou'))
            .mockResolvedValueOnce(discovery('cn-shanghai'));
        apiMocks.listCloudRecommendations
            .mockResolvedValueOnce({ recommendations: [recommendation], cheapest: recommendation, warnings: [] })
            .mockRejectedValueOnce(new Error('price unavailable'));
        const { result } = renderHook(() => useCloudDiscovery({
            accounts: [account],
            canManageAccount: () => true,
            onAccountsRefresh: vi.fn(),
            onPoliciesRefresh: vi.fn(),
            onDashboardRefresh: vi.fn(),
        }));

        await act(async () => { await result.current.discover(account.id); });
        expect(result.current.data.cheapest.region).toBe('cn-hangzhou');

        await act(async () => { await result.current.changeRegion('cn-shanghai'); });

        expect(result.current.data.region).toBe('cn-shanghai');
        expect(result.current.data.cheapest).toBeNull();
        expect(result.current.data.recommendations).toEqual([]);
        expect(result.current.data.instance_types[0].id).toBe('ecs.cn-shanghai');
        await act(async () => { await result.current.save(); });
        expect(apiMocks.autoConfigureCloudAccount).not.toHaveBeenCalled();
    });

    it('does not save while regional resources are incomplete', async () => {
        apiMocks.discoverCloudResources.mockResolvedValue(discovery('cn-hangzhou'));
        apiMocks.listCloudRecommendations.mockResolvedValue({ recommendations: [] });
        const { result } = renderHook(() => useCloudDiscovery({
            accounts: [account],
            canManageAccount: () => true,
            onAccountsRefresh: vi.fn(),
            onPoliciesRefresh: vi.fn(),
            onDashboardRefresh: vi.fn(),
        }));

        await act(async () => { await result.current.discover(account.id); });
        await act(async () => { await result.current.save(); });

        expect(apiMocks.autoConfigureCloudAccount).not.toHaveBeenCalled();
    });

    it('uses the selected region when discovering immediately after the first region save', async () => {
        const unconfiguredAccount = { ...account, region: '' } as API.CloudAccount;
        const onAccountsRefresh = vi.fn().mockResolvedValue(undefined);
        apiMocks.listCloudRegions.mockResolvedValue({ regions: [{ region_id: 'cn-shanghai', local_name: '上海' }] });
        apiMocks.updateCloudAccountRegion.mockResolvedValue({ status: 'ok' });
        apiMocks.discoverCloudResources.mockResolvedValue(discovery('cn-shanghai'));
        apiMocks.listCloudRecommendations.mockResolvedValue({ recommendations: [], cheapest: null, warnings: [] });
        const { result } = renderHook(() => useCloudDiscovery({
            accounts: [unconfiguredAccount],
            canManageAccount: () => true,
            onAccountsRefresh,
            onPoliciesRefresh: vi.fn(),
            onDashboardRefresh: vi.fn(),
        }));

        await act(async () => { await result.current.ensureRegionThen(unconfiguredAccount.id, 'discover'); });
        await act(async () => { await result.current.selectRegion('cn-shanghai'); });

        expect(apiMocks.updateCloudAccountRegion).toHaveBeenCalledWith(unconfiguredAccount.id, 'cn-shanghai');
        expect(apiMocks.discoverCloudResources).toHaveBeenCalledWith(unconfiguredAccount.id, { region: 'cn-shanghai' });
        expect(result.current.data.region).toBe('cn-shanghai');
    });

    it('ignores a stale response when a newer region query finishes first', async () => {
        const firstDiscovery = deferred<ReturnType<typeof discovery>>();
        const secondDiscovery = deferred<ReturnType<typeof discovery>>();
        const firstRecommendations = deferred<{ recommendations: API.CloudRecommendationItem[]; cheapest: API.CloudRecommendationItem; warnings: string[] }>();
        const secondRecommendations = deferred<{ recommendations: API.CloudRecommendationItem[]; cheapest: API.CloudRecommendationItem; warnings: string[] }>();
        const recommendationA = recommendationFor('cn-shanghai');
        const recommendationB = recommendationFor('cn-beijing');
        apiMocks.discoverCloudResources
            .mockReturnValueOnce(firstDiscovery.promise)
            .mockReturnValueOnce(secondDiscovery.promise);
        apiMocks.listCloudRecommendations
            .mockReturnValueOnce(firstRecommendations.promise)
            .mockReturnValueOnce(secondRecommendations.promise);
        const { result } = renderHook(() => useCloudDiscovery({
            accounts: [account],
            canManageAccount: () => true,
            onAccountsRefresh: vi.fn(),
            onPoliciesRefresh: vi.fn(),
            onDashboardRefresh: vi.fn(),
        }));

        let firstChange!: Promise<void>;
        let secondChange!: Promise<void>;
        await act(async () => {
            firstChange = result.current.changeRegion('cn-shanghai');
            secondChange = result.current.changeRegion('cn-beijing');
        });
        await act(async () => {
            secondDiscovery.resolve(discovery('cn-beijing'));
            secondRecommendations.resolve({ recommendations: [recommendationB], cheapest: recommendationB, warnings: [] });
            await secondChange;
        });
        await act(async () => {
            firstDiscovery.resolve(discovery('cn-shanghai'));
            firstRecommendations.resolve({ recommendations: [recommendationA], cheapest: recommendationA, warnings: [] });
            await firstChange;
        });

        expect(result.current.data.region).toBe('cn-beijing');
        expect(result.current.data.images[0].id).toBe('image-cn-beijing');
        expect(result.current.data.cheapest.region).toBe('cn-beijing');
        expect(result.current.form.getFieldValue('region')).toBe('cn-beijing');
        expect(result.current.form.getFieldValue('default_instance_type')).toBe('ecs.cn-beijing');
    });
});
