import type { Evidence } from "../../src/domain/evidence.js";

// Serialized by ab45bf641e95a56a9d6cb8d246818a3d6925eb41. Keep the original
// identifiers: the reversed range was authenticated, rather than tampered.
const historicalRecord = (
  evidenceId: string,
  start: number,
  end: number,
): Evidence => ({
  evidence_id: evidenceId,
  subject: null,
  provider: { id: "fixture", name: "Fixture", version: "1" },
  analysis_profile: null,
  predicate_type: "rea.analysis",
  operation: "inspect_range",
  parameters: {},
  raw_result: null,
  normalized_result: null,
  confidence: "observed",
  authority: "shipped-artifact",
  environment: null,
  limitations: ["Artifact identity is unavailable for this observation."],
  relationship_coverage: null,
  locations: [{ kind: "file-offset-range", start, end }],
  evidence_links: [],
});

export const HISTORICAL_ORDERED_FILE_OFFSET_RECORDS = [
  historicalRecord(
    "ev_192b4120c683ab045e8fd1fc4b1c7679a5739e2e12f96dab4d1da1b59d0929f9",
    0,
    0,
  ),
  historicalRecord(
    "ev_5f113e5e3554d8f6ee7d0bc0bd6506773dff9b63385a71c2d0c06213e8617a76",
    20,
    20,
  ),
  historicalRecord(
    "ev_03d50dbc1aa36e111b4af2bba9a6cbed76691e53aff14bc0facbfceea23a2674",
    20,
    32,
  ),
];

export const HISTORICAL_REVERSED_FILE_OFFSET_RECORD = historicalRecord(
  "ev_55ba4608b57f7f1167dba59583438dd7377ec117ab44d6fdbece88fa7746ab26",
  20,
  10,
);
