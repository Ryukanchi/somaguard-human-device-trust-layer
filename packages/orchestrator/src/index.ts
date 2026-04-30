import type {
  ConsentPurpose,
  PermissionRequest
} from "../../core-types/src/index.js";
import type { GuardianResult } from "../../guardian/src/index.js";
import type { ComposedRiskResult } from "../../composed-risk/src/index.js";
import type { SandboxResult } from "../../sandbox/src/index.js";
import type { SelfTrustResult } from "../../self-trust/src/index.js";
import {
  evaluateConsent,
  type ConsentDecision,
  type ConsentEvaluationInput,
  type ConsentGrant
} from "../../consent-engine/src/index.js";
import {
  createDecisionContext,
  type DecisionContext,
  type PolicyEngine
} from "../../decision-context/src/index.js";

export interface FinalDecision {
  mode: "allowed" | "sandboxed" | "denied" | "requiresApproval";
  reason: string;
  consentDecision: ConsentDecision | null;
  consentValid: boolean | null;
  consentReason: string | null;
  consentSummary: string | null;
}

export interface OrchestratorConsentOptions {
  subjectId: string;
  purpose: ConsentPurpose;
  now: string;
  consentGrants: ConsentGrant[];
}

export interface OrchestratorHandleOptions {
  consent?: OrchestratorConsentOptions;
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

  handle(
    request: PermissionRequest,
    options: OrchestratorHandleOptions = {}
  ): FinalDecision {
    if (this.selfTrustResult.trustLevel === "compromised") {
      return this.withoutConsent({
        mode: "denied",
        reason: `System self-trust is compromised, so SomaGuard denies the request before other decisions: ${this.selfTrustResult.reason}`
      });
    }

    const context = createDecisionContext(request, this.policyEngine);
    const { policyDecision } = context;
    const consentResult = evaluateConsent(
      this.createConsentInput(request, options.consent)
    );

    if (consentResult.decision === "unknown_capability") {
      return this.withConsent(
        {
          mode: "denied",
          reason: `Consent denied unknown capability using fail-closed behavior: ${consentResult.reason}`
        },
        consentResult
      );
    }

    if (consentResult.decision === "missing") {
      return this.withConsent(
        {
          mode: "requiresApproval",
          reason: `Consent is missing for this simulated capability request: ${consentResult.reason}`
        },
        consentResult
      );
    }

    if (consentResult.decision === "revoked") {
      return this.withConsent(
        {
          mode: "denied",
          reason: `Consent was revoked for this simulated capability request: ${consentResult.reason}`
        },
        consentResult
      );
    }

    if (consentResult.decision === "expired") {
      return this.withConsent(
        {
          mode: "denied",
          reason: `Consent expired for this simulated capability request: ${consentResult.reason}`
        },
        consentResult
      );
    }

    if (consentResult.decision === "purpose_mismatch") {
      return this.withConsent(
        {
          mode: "denied",
          reason: `Consent purpose mismatch blocked this simulated request: ${consentResult.reason}`
        },
        consentResult
      );
    }

    const sandboxDecision = this.sandboxEngine.execute(context);
    const guardianResult = this.guardian.analyze();
    const composedRiskResult = this.composedRisk.evaluate();

    if (policyDecision.decision === "deny") {
      return this.withConsent(
        {
          mode: "denied",
          reason: `Policy denied the request: ${policyDecision.reason}`
        },
        consentResult
      );
    }

    if (
      this.selfTrustResult.trustLevel === "degraded" &&
      policyDecision.riskLevel !== "low"
    ) {
      return this.withConsent(
        {
          mode: "sandboxed",
          reason: `System self-trust is degraded, so non-low-risk requests cannot be fully allowed: ${this.selfTrustResult.reason}`
        },
        consentResult
      );
    }

    if (composedRiskResult.riskLevel === "critical") {
      return this.withConsent(
        {
          mode: "requiresApproval",
          reason: `Composed risk requires explicit approval: ${composedRiskResult.reason}`
        },
        consentResult
      );
    }

    if (guardianResult.flagged) {
      return this.withConsent(
        {
          mode: "sandboxed",
          reason: `Guardian flagged the request history, so execution is contained: ${guardianResult.reason}`
        },
        consentResult
      );
    }

    if (sandboxDecision.mode === "sandboxed") {
      return this.withConsent(
        {
          mode: "sandboxed",
          reason: `Sandbox containment selected: ${sandboxDecision.reason}`
        },
        consentResult
      );
    }

    return this.withConsent(
      {
        mode: "allowed",
        reason:
          "Policy allowed the request, consent gate passed, Guardian did not flag history, composed risk is not critical, and sandbox did not require containment."
      },
      consentResult
    );
  }

  private createConsentInput(
    request: PermissionRequest,
    consentOptions: OrchestratorConsentOptions | undefined
  ): ConsentEvaluationInput {
    return {
      subjectId: consentOptions?.subjectId ?? "simulated-human",
      appId: request.appId,
      capabilityId: request.capabilityId,
      purpose: consentOptions?.purpose ?? (request.purpose as ConsentPurpose),
      now: consentOptions?.now ?? request.createdAt,
      grants: consentOptions?.consentGrants ?? []
    };
  }

  private withConsent(
    decision: Pick<FinalDecision, "mode" | "reason">,
    consentResult: ReturnType<typeof evaluateConsent>
  ): FinalDecision {
    return {
      ...decision,
      consentDecision: consentResult.decision,
      consentValid: consentResult.valid,
      consentReason: consentResult.reason,
      consentSummary: consentResult.humanReadableSummary
    };
  }

  private withoutConsent(
    decision: Pick<FinalDecision, "mode" | "reason">
  ): FinalDecision {
    return {
      ...decision,
      consentDecision: null,
      consentValid: null,
      consentReason: null,
      consentSummary: null
    };
  }
}
