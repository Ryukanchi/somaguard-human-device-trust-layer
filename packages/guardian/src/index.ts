import type { AuditEvent, RiskLevel } from "../../core-types/src/index.js";
import type { AuditLog } from "../../audit-log/src/index.js";

export interface GuardianResult {
  flagged: boolean;
  reason: string | null;
}

function isMediumOrHigh(riskLevel: RiskLevel): boolean {
  return riskLevel === "medium" || riskLevel === "high";
}

function hasRiskEscalation(events: AuditEvent[]): boolean {
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];

    if (
      previous?.riskLevel === "low" &&
      current !== undefined &&
      (current.riskLevel === "medium" || current.riskLevel === "high")
    ) {
      return true;
    }
  }

  return false;
}

function hasRepeatedMediumOrHighActions(events: AuditEvent[]): boolean {
  let consecutive = 0;

  for (const event of events) {
    if (isMediumOrHigh(event.riskLevel)) {
      consecutive += 1;

      if (consecutive >= 3) {
        return true;
      }
    } else {
      consecutive = 0;
    }
  }

  return false;
}

function hasMultipleDeniedHighRiskAttempts(events: AuditEvent[]): boolean {
  const deniedHighRiskAttempts = events.filter(
    (event) => event.decision === "deny" && event.riskLevel === "high"
  );

  return deniedHighRiskAttempts.length >= 2;
}

export class Guardian {
  constructor(private readonly auditLog: AuditLog) {}

  analyze(): GuardianResult {
    const events = this.auditLog.getAll();

    if (hasRiskEscalation(events)) {
      return {
        flagged: true,
        reason:
          "Risk escalation detected: audit history moves from low risk to medium or high risk in a short sequence."
      };
    }

    if (hasRepeatedMediumOrHighActions(events)) {
      return {
        flagged: true,
        reason:
          "Repeated medium/high actions detected: three or more medium or high risk events occurred in a row."
      };
    }

    if (events.some((event) => event.riskLevel === "critical")) {
      return {
        flagged: true,
        reason:
          "Critical request presence detected: audit history includes a critical capability request."
      };
    }

    if (hasMultipleDeniedHighRiskAttempts(events)) {
      return {
        flagged: true,
        reason:
          "Suspicious denial pattern detected: multiple denied high-risk attempts appear in the audit history."
      };
    }

    return {
      flagged: false,
      reason: null
    };
  }
}

