require('dotenv').config();

const neo4j = require('neo4j-driver');

const NEO4J_URI = process.env.NEO4J_URI || 'bolt://localhost:7687';
const NEO4J_USER = process.env.NEO4J_USER || 'neo4j';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'sentinelgraph';

let driver = null;

/** Get (or lazily create) the shared Neo4j driver. */
function getDriver() {
  if (!driver) {
    driver = neo4j.driver(
      NEO4J_URI,
      neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD),
      { maxConnectionLifetime: 3 * 60 * 60 * 1000 }
    );
  }
  return driver;
}

async function ping() {
  const d = getDriver();
  const session = d.session();
  try {
    await session.run('RETURN 1');
    return true;
  } finally {
    await session.close();
  }
}

async function close() {
  if (driver) {
    await driver.close();
    driver = null;
  }
}

module.exports = { getDriver, ping, close, NEO4J_URI, NEO4J_USER };