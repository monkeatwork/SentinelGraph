/** CLI wrapper — `npm run ingest:nvd` */
const { ingestNvd } = require('../services/ingest/nvd');

ingestNvd()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error('ingestNvd failed:', e);
    process.exit(1);
  });