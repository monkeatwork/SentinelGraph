/** Global teardown: close live DB connections so jest can exit. */
module.exports = async () => {
  const mongo = require('./src/config/mongo');
  const neo4j = require('./src/config/neo4j');
  try { await mongo.close(); } catch (e) { /* noop */ }
  try { await neo4j.close(); } catch (e) { /* noop */ }
};