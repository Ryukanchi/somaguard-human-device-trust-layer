import type { PermissionRequest } from "../../core-types/src/index.js";
import type { GuardianResult } from "../../guardian/src/index.js";
import type { ComposedRiskResult } from "../../composed-risk/src/index.js";
import type { SandboxResult } from "../../sandbox/src/index.js";
import type { SelfTrustResult } from "../../self-trust/src/index.js";
import {
  createDecisionContext,
  type DecisionContext,
  type PolicyEngine
} from "../../decision-context/src/index.js";

export interface FinalDecision {
  mode: "allowed" | "sandboxed" | "denied" | "requiresApproval";
  reason: string;
}

export interface SandboxExecutor {
  execute(context: DecisionContext): SandboxResult;
}

export interface GuardianAnalyzer {
  analyze(): GuardianResult;
}

export interface ComposedRiskEvaluator {
  evaluate(): ComposedRiskResult;
}

export class Orchestrator {
  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly sandboxEngine: SandboxExecutor,
    private readonly guardian: GuardianAnalyzer,
    private readonly composedRisk: ComposedRiskEvaluator,
    private readonly selfTrustResult: SelfTrustResult = {
      trustLevel: "degraded",
      reason: "Self-trust result was not provided."
    }
  ) {}

  handle(request: PermissionRequest): FinalDecision {
    const context = createDecisionContext(request, this.policyEngine);

    if (this.selfTrustResult.trustLevel === "compromised") {
      return {
        mode: "denied",
        reason: `System self-trust is compromised, so SomaGuard denies the request before other decisions: ${this.selfTrustResult.reason}`
      };
    }

    const { policyDecision } = context;
    const sandboxDecision = this.sandboxEngine.execute(context);
    const guardianResult = this.guardian.analyze();
    const composedRiskResult = this.composedRisk.evaluate();

    if (policyDecision.decision === "deny") {
      return {
        mode: "denied",
        reason: `Policy denied the request: ${policyDecision.reason}`
      };
    }

    if (
      this.selfTrustResult.trustLevel === "degraded" &&
      policyDecision.riskLevel !== "low"
    ) {
      return {
        mode: "sandboxed",
        reason: `System self-trust is degraded, so non-low-risk requests cannot be fully allowed: ${this.selfTrustResult.reason}`
      };
    }

    if (composedRiskResult.riskLevel === "critical") {
      return {
        mode: "requiresApproval",
        reason: `Composed risk requires explicit approval: ${composedRiskResult.reason}`
      };
    }

    if (guardianResult.flagged) {
      return {
        mode: "sandboxed",
        reason: `Guardian flagged the request history, so execution is contained: ${guardianResult.reason}`
      };
    }

    if (sandboxDecision.mode === "sandboxed") {
      return {
        mode: "sandboxed",
        reason: `Sandbox containment selected: ${sandboxDecision.reason}`
      };
    }

    return {
      mode: "allowed",
      reason:
        "Policy allowed the request, Guardian did not flag history, composed risk is not critical, and sandbox did not require containment."
    };
  }
}
