import type {
  AuditEvent,
  PermissionRequest,
  PolicyDecision,
  RiskLevel
} from "../../core-types/src/index.js";
import type { AuditLog } from "../../audit-log/src/index.js";
import { logDecision } from "../../audit-log/src/index.js";

export interface ScenarioStep {
  request: PermissionRequest;
}

export interface Scenario {
  id: string;
  name: string;
  steps: ScenarioStep[];
}

export interface ScenarioResult {
  decisions: PolicyDecision[];
  auditEvents: AuditEvent[];
  flagged: boolean;
  flagReason: string | null;
}

export type PolicyEngine = (request: PermissionRequest) => PolicyDecision;

function isMediumOrHigh(riskLevel: RiskLevel): boolean {
  return riskLevel === "medium" || riskLevel === "high";
}

function detectRiskPattern(
  scenario: Scenario,
  decisions: PolicyDecision[]
): string | null {
  if (
    scenario.steps.some((step) => step.request.capability.riskLevel === "critical")
  ) {
    return "critical interaction detected: scenario includes a critical capability request.";
  }

  if (
    decisions.some(
      (decision) => decision.decision === "deny" && decision.riskLevel === "high"
    )
  ) {
    return "blocked high-risk attempt: at least one high-risk request was denied.";
  }

  let consecutiveMediumOrHigh = 0;

  for (const decision of decisions) {
    if (isMediumOrHigh(decision.riskLevel)) {
      consecutiveMediumOrHigh += 1;

      if (consecutiveMediumOrHigh >= 2) {
        return "risk accumulation: multiple medium or high risk actions occurred in sequence.";
      }
    } else {
      consecutiveMediumOrHigh = 0;
    }
  }

  return null;
}

export class ScenarioEngine {
  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly auditLog: AuditLog
  ) {}

  runScenario(scenario: Scenario): ScenarioResult {
    const decisions: PolicyDecision[] = [];
    const auditEvents: AuditEvent[] = [];

    for (const step of scenario.steps) {
      const decision = this.policyEngine(step.request);
      const event = logDecision(step.request, decision, this.auditLog);

      decisions.push(decision);
      auditEvents.push(event);
    }

    const flagReason = detectRiskPattern(scenario, decisions);

    return {
      decisions,
      auditEvents,
      flagged: flagReason !== null,
      flagReason
    };
  }
}

