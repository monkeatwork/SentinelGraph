/** Review 3 — entity resolver regressions (actor names, multi-word products, noise words). */
const { resolveEntities } = require('../src/services/entityResolver');

describe('Entity resolver', () => {
  test('flagship Log4j question still resolves Log4Shell', async () => {
    const r = await resolveEntities('Which adversary groups exploit Log4j, and how?');
    expect(r.cves).toContain('CVE-2021-44228');
    expect(r.cpeNames.every((c) => c.includes(':log4j:'))).toBe(true);
  });

  test('threat actor named in the question resolves by name', async () => {
    const r = await resolveEntities('What techniques does APT29 use and how can they be mitigated?');
    expect(r.mitreIds).toContain('G0016');
    expect(r.cpeNames).toEqual([]); // "can" must not match "officescan"
  });

  test('multi-word product prefers the vendor product over third-party add-ons', async () => {
    const r = await resolveEntities('If my organisation runs Microsoft Exchange, who can attack us?');
    expect(r.cpeNames.length).toBeGreaterThan(0);
    expect(r.cpeNames.every((c) => c.includes(':microsoft:exchange_server:'))).toBe(true);
  });

  test('digits inside a CVE id are not used as product terms', async () => {
    const r = await resolveEntities('Which groups exploit CVE-2017-0144?');
    expect(r.cves).toEqual(['CVE-2017-0144']);
    expect(r.cpeNames).toEqual([]);
  });
});
