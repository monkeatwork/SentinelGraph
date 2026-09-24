/** CLI wrapper — `npm run ingest:cisa` */
const { ingestCisaKev } = require('../services/ingest/cisa-kev');

ingestCisaKev()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error('ingestCisaKev failed:', e);
    process.exit(1);
  });