import { describe, expect, it } from "vitest";
import { AuditLog } from "../packages/audit-log/src/index.js";
import type { AuditEvent, RiskLevel } from "../packages/core-types/src/index.js";
import { Guardian } from "../packages/guardian/src/index.js";

function event(input: {
  id: string;
  riskLevel: RiskLevel;
  decision?: "allow" | "deny";
}): AuditEvent {
  return {
    id: input.id,
    eventType: "policy_decision_recorded",
    timestamp: `2026-01-01T00:00:0${input.id.at(-1) ?? "0"}.000Z`,
    appId: "app-test",
    deviceId: "device-test",
    capabilityId: `cap-${input.id}`,
    capabilityName: "Test capability",
    decision: input.decision ?? "allow",
    riskLevel: input.riskLevel,
    reason: "Test audit event.",
    requiresApproval: input.riskLevel === "critical",
    audit: true,
    humanReadableSummary: "Test audit event.",
    simulationOnly: true
  };
}

function analyze(events: AuditEvent[]) {
  const auditLog = new AuditLog();

  for (const auditEvent of events) {
    auditLog.record(auditEvent);
  }

  return new Guardian(auditLog).analyze();
}

describe("Guardian", () => {
  it("does not flag safe history", () => {
    const result = analyze([
      event({ id: "event-1", riskLevel: "low" }),
      event({ id: "event-2", riskLevel: "low" })
    ]);

    expect(result).toEqual({
      flagged: false,
      reason: null
    });
  });

  it("flags risk escalation", () => {
    const result = analyze([
      event({ id: "event-1", riskLevel: "low" }),
      event({ id: "event-2", riskLevel: "medium" })
    ]);

    expect(result.flagged).toBe(true);
    expect(result.reason).toContain("Risk escalation detected");
  });

  it("flags repeated high-risk actions", () => {
    const result = analyze([
      event({ id: "event-1", riskLevel: "high" }),
      event({ id: "event-2", riskLevel: "medium" }),
      event({ id: "event-3", riskLevel: "high" })
    ]);

    expect(result.flagged).toBe(true);
    expect(result.reason).toContain("Repeated medium/high actions detected");
  });

  it("flags critical request presence", () => {
    const result = analyze([
      event({ id: "event-1", riskLevel: "medium" }),
      event({ id: "event-2", riskLevel: "critical", decision: "deny" })
    ]);

    expect(result.flagged).toBe(true);
    expect(result.reason).toContain("Critical request presence detected");
  });
});

