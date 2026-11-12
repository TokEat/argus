import { describe, expect, it } from 'vitest';
import { getAssetDiscoveryCompletions } from './syntaxCatalog';

describe('getAssetDiscoveryCompletions', () => {
    it('completes fields at the beginning and after provider boolean operators', () => {
        expect(getAssetDiscoveryCompletions('fofa', 'dom')[0]?.value).toBe('domain=');
        expect(getAssetDiscoveryCompletions('fofa', 'title="Acme" && dom')[0]?.value)
            .toBe('title="Acme" && domain=');
        expect(getAssetDiscoveryCompletions('quake', 'service:"http" AND por')[0]?.value)
            .toBe('service:"http" AND port:');
    });

    it('does not treat text inside quoted values as a field prefix', () => {
        expect(getAssetDiscoveryCompletions('fofa', 'title="Acme dom')).toEqual([]);
        expect(getAssetDiscoveryCompletions('fofa', 'title="Acme domain"')).toEqual([]);
        expect(getAssetDiscoveryCompletions('fofa', 'title="Acme \\"team dom')).toEqual([]);
    });

    it('handles escaped quotes and resumes completion after a closed value', () => {
        const expression = 'title="Acme \\"team" && dom';
        expect(getAssetDiscoveryCompletions('fofa', expression)[0]?.value)
            .toBe('title="Acme \\"team" && domain=');
    });

    it('does not complete a whitespace-delimited bare value', () => {
        expect(getAssetDiscoveryCompletions('fofa', 'title=Acme dom')).toEqual([]);
    });
});
