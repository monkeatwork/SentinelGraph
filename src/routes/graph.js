const express = require('express');
const { ObjectId } = require('mongodb');

const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { requireAuth, requireRole } = require('../middleware/auth');
const { LABEL_KEY, LABELS, keyOf, ENTITY_LABELS, httpError } = require('../services/graphMeta');

const router = express.Router();

function cleanProps(props) {
  const p = { ...props };
  delete p.mitreId; delete p.cveId; delete p.cpeName; delete p.sectorName; // key is path-owned
  return p;
}

/** POST /api/graph/:label — admin only; CREATE a new node (duplicate key → 409) */
router.post('/:label', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { label } = req.params;
    const keyProp = keyOf(label);
    if (!keyProp) throw httpError(400, 'BAD_REQUEST', `Unknown label '${label}'. Valid: ${LABELS.join(', ')}`);
    const body = req.body || {};
    const key = body[keyProp];
    if (!key) throw httpError(400, 'BAD_REQUEST', `Property '${keyProp}' is required`);
    const props = cleanProps(body);
    props[keyProp] = key;

    const driver = getDriver();
    session = driver.session();
    await session.run(
      `CREATE (n:${label} {${keyProp}: $key})
       SET n += $props
       RETURN n`,
      { key, props }
    );

    // Mirror into Mongo entities where the label is an entity label
    const db = await getDb();
    if (ENTITY_LABELS.has(label)) {
      await db.collection('entities').updateOne(
        { mitreId: key },
        {
          $set: {
            mitreId: key,
            entityType: label,
            name: props.name || null,
            aliases: props.aliases || [],
            neo4jSynced: true,
            updatedAt: new Date(),
          },
          $setOnInsert: { createdAt: new Date() },
        },
        { upsert: true }
      );
    }

    res.status(201).json({ ok: true, label, keyProp, key, props });
  } catch (e) {
    if (e.code === 'Neo.ClientError.Schema.ConstraintValidationFailed') {
      return next(httpError(409, 'DUPLICATE_KEY', `Node with that ${keyOf(req.params.label)} already exists`));
    }
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/graph/:label/:key — fetch a node's properties */
router.get('/:label/:key', requireAuth, async (req, res, next) => {
  let session;
  try {
    const { label, key } = req.params;
    const keyProp = keyOf(label);
    if (!keyProp) throw httpError(400, 'BAD_REQUEST', `Unknown label '${label}'`);
    const driver = getDriver();
    session = driver.session();
    const r = await session.run(
      `MATCH (n:${label} {${keyProp}: $key}) RETURN n`,
      { key }
    );
    if (!r.records.length) throw httpError(404, 'NOT_FOUND', `No ${label} with ${keyProp} '${key}'`);
    res.json({ node: r.records[0].get('n').properties, label, keyProp, key });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** PATCH /api/graph/:label/:key — admin only; update props + mirror to Mongo entities */
router.patch('/:label/:key', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { label, key } = req.params;
    const keyProp = keyOf(label);
    if (!keyProp) throw httpError(400, 'BAD_REQUEST', `Unknown label '${label}'`);
    const props = cleanProps(req.body || {});
    if (!Object.keys(props).length) throw httpError(400, 'BAD_REQUEST', 'No updatable properties supplied');

    const driver = getDriver();
    session = driver.session();
    const r = await session.run(
      `MATCH (n:${label} {${keyProp}: $key})
       SET n += $props
       RETURN n`,
      { key, props }
    );
    if (!r.records.length) throw httpError(404, 'NOT_FOUND', `No ${label} with ${keyProp} '${key}'`);

    const db = await getDb();
    if (ENTITY_LABELS.has(label)) {
      await db.collection('entities').updateOne(
        { mitreId: key },
        { $set: { ...props, entityType: label, name: props.name ?? undefined, neo4jSynced: true, updatedAt: new Date() } }
      );
    }
    res.json({ ok: true, node: r.records[0].get('n').properties });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** DELETE /api/graph/:label/:key — admin only; DETACH DELETE + mirror deletion in Mongo */
router.delete('/:label/:key', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { label, key } = req.params;
    const keyProp = keyOf(label);
    if (!keyProp) throw httpError(400, 'BAD_REQUEST', `Unknown label '${label}'`);
    const driver = getDriver();
    session = driver.session();
    const r = await session.run(
      `MATCH (n:${label} {${keyProp}: $key})
       DETACH DELETE n
       RETURN count(n) AS c`,
      { key }
    );
    const deleted = r.records[0].get('c').toNumber();
    if (!deleted) throw httpError(404, 'NOT_FOUND', `No ${label} with ${keyProp} '${key}'`);

    const db = await getDb();
    if (keyProp === 'mitreId') {
      await db.collection('entities').deleteOne({ mitreId: key });
    }
    res.json({ ok: true, deleted });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/graph/:label/:key/neighbors — node + 1-hop neighbourhood (dashboard viz) */
router.get('/:label/:key/neighbors', requireAuth, async (req, res, next) => {
  let session;
  try {
    const { label, key } = req.params;
    const keyProp = keyOf(label);
    if (!keyProp) throw httpError(400, 'BAD_REQUEST', `Unknown label '${label}'`);
    const driver = getDriver();
    session = driver.session();
    const r = await session.run(
      `MATCH (n:${label} {${keyProp}: $key})
       OPTIONAL MATCH (n)-[rel]-(m)
       WHERE m IS NOT NULL
       WITH n, m, type(rel) AS rt, CASE WHEN startNode(rel) = n THEN 'out' ELSE 'in' END AS dir
       RETURN n AS node,
              { key: coalesce(m.mitreId, m.cveId, m.cpeName, m.sectorName),
                label: labels(m)[0], name: m.name, rel: rt, direction: dir } AS neighbor
       LIMIT 80`,
      { key }
    );
    if (!r.records.length) throw httpError(404, 'NOT_FOUND', `No ${label} with ${keyProp} '${key}'`);
    const node = r.records[0].get('node');
    const neighbors = r.records.map((rec) => rec.get('neighbor')).filter((nb) => nb && nb.key);
    res.json({
      node: { label, keyProp, key, name: node.properties.name || node.properties.product || key, props: node.properties },
      neighbors,
    });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/graph/search?q= — full-text entity search across both stores */
router.get('/search', requireAuth, async (req, res, next) => {
  let session;
  try {
    const q = (req.query.q || '').trim();
    if (!q) throw httpError(400, 'BAD_REQUEST', 'q is required');
    const driver = getDriver();
    session = driver.session();
    const [ft, db] = await Promise.all([
      session.run(
        `CALL db.index.fulltext.queryNodes('entity_name_ft', $q) YIELD node, score
         RETURN node.mitreId AS id, labels(node)[0] AS label, node.name AS name, score
         ORDER BY score DESC LIMIT 20`,
        { q }
      ),
      getDb(),
    ]);
    const neoSearch = ft.records.map((r) => ({
      mitreId: r.get('id'),
      label: r.get('label'),
      name: r.get('name'),
      score: r.get('score'),
    }));
    let mongoSearch = [];
    try {
      mongoSearch = await db
        .collection('entities')
        .find({ $text: { $search: q } })
        .project({ mitreId: 1, entityType: 1, name: 1, _id: 0 })
        .limit(10)
        .toArray();
    } catch (e) { /* index missing */ }
    res.json({ q, results: { neo4j: neoSearch, mongo: mongoSearch } });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

module.exports = router;