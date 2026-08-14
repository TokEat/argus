import { describe, expect, it } from 'vitest';
import { buildScanPolicy, presetDefaults } from './ScanPolicyComposer';

const subdomainDictionary: API.SubdomainDictionary = {
	id: 'subdomains-1', project_id: 'project-1', name: 'environment labels', revision: 3,
	sha256: 'a'.repeat(64), count: 12, created_at: '2026-08-13T00:00:00Z',
};

describe('scan policy subdomain discovery', () => {
	it('keeps behavior probes independent from active paths across presets', () => {
		expect(buildScanPolicy({ preset: 'quick' }, []).capabilities.behavior_probe).toBe(false);
		expect(buildScanPolicy({ preset: 'standard' }, []).capabilities).toMatchObject({ behavior_probe: true, directory_probe: false });
		expect(buildScanPolicy({ preset: 'deep' }, []).capabilities).toMatchObject({ behavior_probe: true, directory_probe: true });
	});
	it('uses depth two for the deep preset', () => {
		expect(presetDefaults.deep.subdomain_bruteforce).toBe(true);
		expect(presetDefaults.deep.subdomain_bruteforce_depth).toBe(2);
		const policy = buildScanPolicy({ preset: 'deep' }, []);
		expect(policy.subdomains.bruteforce_depth).toBe(2);
	});

	it('binds an immutable additive dictionary and an explicit depth', () => {
		const policy = buildScanPolicy({
			preset: 'deep', subdomain_bruteforce: true, subdomain_bruteforce_depth: 4,
			subdomain_books: [subdomainDictionary.id],
		}, [], [subdomainDictionary]);
		expect(policy.subdomains).toEqual({
			bruteforce_depth: 4,
			wordlists: [{
				id: subdomainDictionary.id, revision: 3,
				sha256: subdomainDictionary.sha256, count: 12,
			}],
		});
	});

	it('does not send a depth when bruteforce is disabled', () => {
		const policy = buildScanPolicy({ preset: 'standard' }, []);
		expect(policy.capabilities.subdomain_bruteforce).toBe(false);
		expect(policy.subdomains.bruteforce_depth).toBe(0);
	});
});
