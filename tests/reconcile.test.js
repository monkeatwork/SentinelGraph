const { reconcile, driftCount } = require('../src/scripts/reconcile');

describe('Cross-store reconciliation', () => {
  test('reports both directions for entities and vulnerabilities', async () => {
    const r = await reconcile();
    for (const side of [r.entities, r.vulnerabilities]) {
      expect(side.mongoCount).toBeGreaterThan(0);
      expect(side.graphCount).toBeGreaterThan(0);
      expect(Array.isArray(side.missingInGraph)).toBe(true);
      expect(Array.isArray(side.missingInMongo)).toBe(true);
    }
    expect(Array.isArray(r.entities.labelMismatch)).toBe(true);
    expect(Array.isArray(r.entities.multiLabel)).toBe(true);
    expect(typeof driftCount(r)).toBe('number');
  });

  test('ingested CVEs agree across stores', async () => {
    const r = await reconcile();
    expect(r.vulnerabilities.missingInGraph).toEqual([]);
    expect(r.vulnerabilities.missingInMongo).toEqual([]);
  });

  test('graph CRUD tests leave no residue in Mongo', async () => {
    const r = await reconcile();
    expect(r.entities.missingInGraph.filter((id) => /^T9TEST/.test(id))).toEqual([]);
  });
});
