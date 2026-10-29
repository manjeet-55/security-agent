import type { EvidenceRecord } from '../evidence/store.js';

const OMITTED = '[omitted: page bodies are not shared with AI clients; the file under .secagent/evidence/ has it]';

/**
 * An evidence record as an AI client may see it; the file on disk is unchanged. A page fetch keeps its status, headers and cookie
 * names and flags, but not the page body. Cookie values never reach evidence (the observation redacts them when it is captured),
 * and every other kind of evidence is free of secrets by construction.
 */
export function redactEvidence(record: EvidenceRecord): EvidenceRecord {
  if (record.kind !== 'http' || typeof record.data !== 'object' || record.data === null || !('bodySnippet' in record.data)) return record;
  return { ...record, data: { ...record.data, bodySnippet: OMITTED } };
}
