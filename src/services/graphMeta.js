/**
 * Graph label metadata — one key per label, used by CRUD routes + mirroring.
 */
const LABEL_KEY = {
  ThreatActor: 'mitreId',
  Campaign: 'mitreId',
  Malware: 'mitreId',
  Technique: 'mitreId',
  Tactic: 'mitreId',
  Mitigation: 'mitreId',
  Vulnerability: 'cveId',
  Software: 'cpeName',
  Sector: 'sectorName',
};

const LABELS = Object.keys(LABEL_KEY);

function keyOf(label) {
  return LABEL_KEY[label] || null;
}

/** Entity-style labels mirror into the Mongo `entities` collection. */
const ENTITY_LABELS = new Set(['ThreatActor', 'Campaign', 'Malware', 'Technique', 'Tactic', 'Mitigation']);

function httpError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

module.exports = { LABEL_KEY, LABELS, keyOf, ENTITY_LABELS, httpError };