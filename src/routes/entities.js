const express = require('express');

const { getDb } = require('../config/mongo');
const { getDriver } = require('../config/neo4j');
const { requireAuth, requireRole } = require('../middleware/auth');
const { ENTITY_LABELS, httpError } = require('../services/graphMeta');

const router = express.Router();

/** POST /api/entities — admin only; insert document + mirror graph node */
router.post('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { mitreId, entityType, name, aliases, description, externalRefs } = req.body || {};
    if (!mitreId || !entityType) throw httpError(400, 'BAD_REQUEST', 'mitreId and entityType are required');
    if (!ENTITY_LABELS.has(entityType)) {
      throw httpError(400, 'BAD_REQUEST', `entityType must be one of: ${[...ENTITY_LABELS].join(', ')} (Software, Vulnerability and Sector are not mitreId-keyed)`);
    }

    const db = await getDb();
    const doc = {
      mitreId,
      entityType,
      name: name || mitreId,
      aliases: aliases || [],
      description: description || '',
      externalRefs: externalRefs || [],
      neo4jSynced: true,
      updatedAt: new Date(),
      createdAt: new Date(),
    };
    try {
      await db.collection('entities').insertOne(doc);
    } catch (e) {
      if (e.code === 11000) throw httpError(409, 'DUPLICATE_KEY', `mitreId '${mitreId}' already exists`);
      throw e;
    }

    const driver = getDriver();
    session = driver.session();
    await session.run(
      `MERGE (n:${entityType} {mitreId: $mitreId})
       SET n.name = $name, n.aliases = $aliases`,
      { mitreId, name: doc.name, aliases: doc.aliases }
    );

    res.status(201).json({ entity: doc });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** GET /api/entities — list with filters (entityType, q, limit) */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { entityType, q, limit = 50 } = req.query;
    const db = await getDb();
    const filter = {};
    if (entityType) filter.entityType = entityType;
    let docs;
    if (q) {
      try {
        docs = await db.collection('entities').find({ ...filter, $text: { $search: String(q) } })
          .limit(Number(limit) || 50).toArray();
      } catch (e) {
        docs = await db.collection('entities').find({ ...filter, name: { $regex: String(q), $options: 'i' } })
          .limit(Number(limit) || 50).toArray();
      }
    } else {
      docs = await db.collection('entities').find(filter).limit(Number(limit) || 50).toArray();
    }
    res.json({ count: docs.length, entities: docs });
  } catch (e) {
    next(e);
  }
});

/** GET /api/entities/:mitreId */
router.get('/:mitreId', requireAuth, async (req, res, next) => {
  try {
    const db = await getDb();
    const doc = await db.collection('entities').findOne({ mitreId: req.params.mitreId });
    if (!doc) throw httpError(404, 'NOT_FOUND', `No entity with mitreId '${req.params.mitreId}'`);
    res.json({ entity: doc });
  } catch (e) {
    next(e);
  }
});

/** PUT /api/entities/:mitreId — admin only; update doc + graph node */
router.put('/:mitreId', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { mitreId } = req.params;
    const db = await getDb();
    const existing = await db.collection('entities').findOne({ mitreId });
    if (!existing) throw httpError(404, 'NOT_FOUND', `No entity with mitreId '${mitreId}'`);

    const { name, aliases, description, externalRefs, entityType } = req.body || {};
    const $set = { updatedAt: new Date() };
    if (name !== undefined) $set.name = name;
    if (aliases !== undefined) $set.aliases = aliases;
    if (description !== undefined) $set.description = description;
    if (externalRefs !== undefined) $set.externalRefs = externalRefs;

    // a type change would relabel the Mongo doc but not the graph node (cross-store drift)
    if (entityType && entityType !== existing.entityType) {
      throw httpError(400, 'BAD_REQUEST', 'entityType cannot be changed; delete the entity and create it again');
    }

    await db.collection('entities').updateOne({ mitreId }, { $set });

    const driver = getDriver();
    session = driver.session();
    await session.run(
      `MATCH (n:${existing.entityType} {mitreId: $mitreId})
       SET n.name = COALESCE($name, n.name), n.aliases = COALESCE($aliases, n.aliases)`,
      { mitreId, name: name ?? null, aliases: aliases ?? null }
    );
    const updated = await db.collection('entities').findOne({ mitreId });
    res.json({ entity: updated });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

/** DELETE /api/entities/:mitreId — admin only; delete doc + DETACH DELETE node */
router.delete('/:mitreId', requireAuth, requireRole('admin'), async (req, res, next) => {
  let session;
  try {
    const { mitreId } = req.params;
    const db = await getDb();
    const doc = await db.collection('entities').findOne({ mitreId });
    if (!doc) throw httpError(404, 'NOT_FOUND', `No entity with mitreId '${mitreId}'`);
    await db.collection('entities').deleteOne({ mitreId });

    const driver = getDriver();
    session = driver.session();
    await session.run(
      `MATCH (n:${doc.entityType} {mitreId: $mitreId}) DETACH DELETE n`,
      { mitreId }
    );
    res.json({ ok: true, deleted: mitreId });
  } catch (e) {
    next(e);
  } finally {
    if (session) await session.close();
  }
});

module.exports = router;