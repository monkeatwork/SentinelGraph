/** CLI wrapper — `npm run ingest:attack` */
const { ingestAttack } = require('../services/ingest/attack-stix');

ingestAttack()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error('ingestAttack failed:', e);
    process.exit(1);
  });