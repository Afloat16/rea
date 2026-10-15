import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { z } from "zod";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { AnalysisCancelledError } from "../../../src/domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { EvidenceIntegrityError } from "../../../src/domain/evidenceErrors.js";
import { err, ok } from "../../../src/domain/result.js";
import { silentLogger } from "../../../src/logger.js";
import { createEvidenceToolHandler } from "../../../src/server/contractToolHandler.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { toolRegistrationOptions } from "../../../src/server/toolRegistrationOptions.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

const targetContent = {
  provenance: { untrusted_content: true, source: "analysis_target" },
};

it.each([false, true])(
  "preserves the original partial failure when recording fails: %s",
  async (recordingFails) => {
    const input = { path: "/fixture/recording.pcap", fields: ["frame.number"] };
    const partial = createEvidence(
      undefined,
      { id: "fixture", name: "Completed capture fixture", version: "1" },
      {
        operation: "inspect_packet_capture",
        parameters: input,
        result: { packets: [{ "frame.number": ["1"] }] },
        confidence: "observed",
      },
    );
    const capturedOutput = {
      stdout: "observed capture output",
      stderr: "capture diagnostic",
      truncated: false,
    };
    const failure = new AnalysisCancelledError("inspect_packet_capture", {
      partialObservation: partial,
      capturedOutput,
    });
    const attempts: Evidence[] = [];
    const recordEvidence = (evidence: Evidence) => {
      attempts.push(evidence);
      return recordingFails
        ? err(new EvidenceIntegrityError("fixture ledger refused the record"))
        : ok("added" as const);
    };
    const delivery = new ToolResultDelivery(4096);
    const server = new EvidenceMcpServer(
      { name: "partial-recording-test", version: "1" },
      { capabilities: {} },
      recordEvidence,
      delivery,
    );
    const contract = toolContract("inspect_packet_capture");
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      createEvidenceToolHandler(
        server,
        async () => err(failure),
        silentLogger,
        recordEvidence,
      )(contract),
    );
    server.registerTool("healthy", { inputSchema: z.object({}) }, async () => ({
      content: [{ type: "text", text: "still connected" }],
    }));
    const client = new Client({
      name: "partial-recording-client",
      version: "1",
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const reply = await client.callTool({
        name: contract.name,
        arguments: input,
      });
      const projected = parseMcpToolError(reply).error;
      expect(projected).toMatchObject({
        code: "cancelled",
        category: "cancelled",
        details: {
          operation: "inspect_packet_capture",
          captured_output: capturedOutput,
        },
      });
      expect(attempts).toEqual([partial]);
      if (recordingFails) {
        expect(projected.details).toMatchObject({
          partial_observation: partial,
          retention: "failed",
          retention_error: {
            code: "evidence_integrity_mismatch",
            details: { reason: "fixture ledger refused the record" },
            remediation: { action: expect.any(String) },
          },
        });
        expect(projected.details).not.toHaveProperty("evidence_reference");
      } else {
        expect(projected.details).toMatchObject({
          partial_observation: {
            kind: "retained-evidence",
            evidence_id: partial.evidence_id,
          },
        });
        expect(projected.details).not.toHaveProperty("retention_error");
      }
      expect(reply.structuredContent).toBeUndefined();
      expect(reply._meta).toEqual(targetContent);
      expect(Buffer.byteLength(JSON.stringify(reply))).toBeLessThanOrEqual(
        delivery.resultBudgetBytes,
      );
      const healthy = await client.callTool({ name: "healthy", arguments: {} });
      expect(healthy.content).toEqual([
        { type: "text", text: "still connected" },
      ]);
    } finally {
      await Promise.all([client.close(), server.close()]);
    }
  },
);
