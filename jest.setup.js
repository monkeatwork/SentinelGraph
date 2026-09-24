require('dotenv').config();
// Integration tests talk to the live local containers:
//   docker compose up -d   (required before `npm test`)
process.env.EMBEDDING_MODE = process.env.EMBEDDING_MODE || 'hash'; // fast, deterministic tests