require('dotenv').config();

const { MongoClient } = require('mongodb');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelgraph';
const DB_NAME = process.env.MONGO_DB || 'sentinelgraph';

let client = null;
let db = null;

/** Get (or lazily create) the shared Mongo client + db handle. */
async function getDb() {
  if (db) return db;
  client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
  });
  await client.connect();
  db = client.db(DB_NAME);
  return db;
}

async function ping() {
  const d = await getDb();
  await d.command({ ping: 1 });
  return true;
}

async function close() {
  if (client) {
    await client.close();
    client = null;
    db = null;
  }
}

module.exports = { getDb, ping, close, MONGO_URI, DB_NAME };