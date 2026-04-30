import { describe, expect, it } from "vitest";
import type {
  AppIdentity,
  ConsentPurpose,
  Device,
  DeviceCapability,
  PermissionRequest,
  PolicyDecision,
  RiskLevel
} from "../packages/core-types/src/index.js";
import {
  createConsentGrant,
  expireConsentGrant,
  revokeConsentGrant,
  type ConsentGrant
} from "../packages/consent-engine/src/index.js";
import type { ComposedRiskResult } from "../packages/composed-risk/src/index.js";
import type { GuardianResult } from "../packages/guardian/src/index.js";
import { Orchestrator } from "../packages/orchestrator/src/index.js";
import type { SandboxResult } from "../packages/sandbox/src/index.js";
import type { SelfTrustResult } from "../packages/self-trust/src/index.js";

const app: AppIdentity = {
  id: "app-test",
  name: "Test App",
  trustLevel: "trusted",
  trusted: true,
  declaredPurpose: "Orchestrator test app.",
  simulationOnly: true
};

const device: Device = {
  id: "device-test",
  name: "Test Device Sim",
  type: "wearable_sim",
  safetyMode: "observe_only",
  capabilities: [],
  simulationOnly: true
};

const trustedSelfTrust: SelfTrustResult = {
  trustLevel: "trusted",
  reason: "All expected components are present."
};

const now = "2026-04-30T12:00:00.000Z";
const grantedAt = "2026-04-30T09:00:00.000Z";

function defaultCapabilityId(riskLevel: RiskLevel): string {
  if (riskLevel === "low") {
    return "read_battery";
  }
  if (riskLevel === "medium") {
    return "read_motion";
  }
  if (riskLevel === "high") {
    return "read_heart_rate";
  }
  return "read_stress_signal";
}

function defaultPurpose(capabilityId: string): ConsentPurpose {
  return capabilityId === "read_battery" ? "device_maintenance" : "wellness_summary";
}

function capability(
  riskLevel: RiskLevel,
  capabilityId = defaultCapabilityId(riskLevel)
): DeviceCapability {
  return {
    id: capabilityId,
    name: `${riskLevel} capability`,
    accessType: "read",
    riskLevel,
    description: "Test capability.",
    simulationOnly: true
  };
}

function request(
  riskLevel: RiskLevel,
  capabilityId = defaultCapabilityId(riskLevel),
  purpose = defaultPurpose(capabilityId)
): PermissionRequest {
  const selectedCapability = capability(riskLevel, capabilityId);

  return {
    id: `request-${riskLevel}-${capabilityId}`,
    appId: app.id,
    deviceId: device.id,
    capabilityId: selectedCapability.id,
    app,
    device,
    capability: selectedCapability,
    requestedAccessType: selectedCapability.accessType,
    purpose,
    createdAt: "2026-04-29T00:00:00.000Z",
    simulationOnly: true
  };
}

function policyDecision(input: {
  decision: "allow" | "deny";
  riskLevel: RiskLevel;
  reason?: string;
}): PolicyDecision {
  return {
    requestId: `request-${input.riskLevel}`,
    decision: input.decision,
    riskLevel: input.riskLevel,
    reason: input.reason ?? "Test policy decision.",
    requiresApproval: false,
    audit: true,
    humanReadableSummary: "Test policy decision.",
    simulationOnly: true
  };
}

function grantFor(
  consentRequest: PermissionRequest,
  overrides: Partial<Parameters<typeof createConsentGrant>[0]> = {}
): ConsentGrant {
  return createConsentGrant({
    subjectId: "simulated-human",
    appId: consentRequest.appId,
    capabilityId: consentRequest.capabilityId,
    purpose: consentRequest.purpose as ConsentPurpose,
    grantedAt,
    expiresAt: "2026-05-01T00:00:00.000Z",
    ...overrides
  });
}

function consentOptions(
  consentRequest: PermissionRequest,
  consentGrants: ConsentGrant[],
  purpose = consentRequest.purpose as ConsentPurpose,
  subjectId = "simulated-human"
) {
  return {
    consent: {
      subjectId,
      purpose,
      now,
      consentGrants
    }
  };
}

function buildOrchestrator(input: {
  policy: PolicyDecision;
  sandbox: SandboxResult;
  guardian?: GuardianResult;
  composedRisk?: ComposedRiskResult;
  selfTrustResult?: SelfTrustResult;
}) {
  return new Orchestrator(
    () => input.policy,
    {
      execute: () => input.sandbox
    },
    {
      analyze: () => input.guardian ?? { flagged: false, reason: null }
    },
    {
      evaluate: () =>
        input.composedRisk ?? {
          riskLevel: "low",
          reason: "Composed risk is low."
        }
    },
    input.selfTrustResult
  );
}

describe("Orchestrator", () => {
  it("allows low safe requests", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("allowed");
    expect(finalDecision.reason).toContain("Policy allowed");
  });

  it("sandboxes medium risk requests", () => {
    const consentRequest = request("medium");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "medium" }),
      sandbox: {
        mode: "sandboxed",
        reason: "Medium-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("Sandbox containment selected");
  });

  it("sandboxes when Guardian flags history", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      guardian: {
        flagged: true,
        reason: "Risk escalation detected."
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("Guardian flagged");
  });

  it("requires approval when composed risk is critical", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      composedRisk: {
        riskLevel: "critical",
        reason: "Composed risk escalated to critical."
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("requiresApproval");
    expect(finalDecision.reason).toContain("Composed risk requires explicit approval");
  });

  it("denies when policy denies", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({
        decision: "deny",
        riskLevel: "high",
        reason: "The app is untrusted and requested high risk."
      }),
      sandbox: {
        mode: "denied",
        reason: "Request denied by policy.",
        simulated: true
      },
      composedRisk: {
        riskLevel: "critical",
        reason: "Composed risk escalated to critical."
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.reason).toContain("Policy denied");
  });

  it("compromised self-trust overrides everything", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      guardian: {
        flagged: false,
        reason: null
      },
      composedRisk: {
        riskLevel: "low",
        reason: "Composed risk is low."
      },
      selfTrustResult: {
        trustLevel: "compromised",
        reason: "Integrity check failed."
      }
    });

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.reason).toContain("self-trust is compromised");
  });

  it("degraded self-trust restricts high risk", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: {
        trustLevel: "degraded",
        reason: "The guardian component is missing."
      }
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("self-trust is degraded");
    expect(finalDecision.reason).toContain("non-low-risk");
  });

  it("trusted self-trust behaves as before", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("allowed");
    expect(finalDecision.reason).toContain("Policy allowed");
  });

  it("evaluates policy exactly once and reuses the decision context", () => {
    const sharedDecision = policyDecision({
      decision: "allow",
      riskLevel: "low",
      reason: "Single evaluation decision."
    });
    let policyCalls = 0;
    let sandboxSawSharedDecision = false;

    const orchestrator = new Orchestrator(
      () => {
        policyCalls += 1;
        return sharedDecision;
      },
      {
        execute: (context) => {
          sandboxSawSharedDecision = context.policyDecision === sharedDecision;
          return {
            mode: "allowed",
            reason: "Sandbox reused the decision context.",
            simulated: true
          };
        }
      },
      {
        analyze: () => ({ flagged: false, reason: null })
      },
      {
        evaluate: () => ({
          riskLevel: "low",
          reason: "Composed risk is low."
        })
      },
      trustedSelfTrust
    );

    const finalDecision = orchestrator.handle(request("low"));

    expect(finalDecision.mode).toBe("allowed");
    expect(policyCalls).toBe(1);
    expect(sandboxSawSharedDecision).toBe(true);
  });

  it("missing selfTrustResult defaults to degraded", () => {
    const consentRequest = request("medium");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "medium" }),
      sandbox: {
        mode: "sandboxed",
        reason: "Medium-risk simulated request requires containment.",
        simulated: true
      }
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("Self-trust result was not provided.");
  });

  it("missing selfTrustResult does not fully allow high-risk requests", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      }
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.mode).not.toBe("allowed");
    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("self-trust is degraded");
  });

  it("valid consent allows normal flow to continue", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.consentDecision).toBe("valid");
    expect(finalDecision.consentValid).toBe(true);
    expect(finalDecision.mode).toBe("sandboxed");
  });

  it("missing consent returns requiresApproval for sensitive capability", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [])
    );

    expect(finalDecision.mode).toBe("requiresApproval");
    expect(finalDecision.consentDecision).toBe("missing");
    expect(finalDecision.reason).toContain("Consent is missing");
  });

  it("revoked consent denies", () => {
    const consentRequest = request("high");
    const revokedGrant = revokeConsentGrant(
      grantFor(consentRequest),
      "2026-04-30T10:00:00.000Z"
    );
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [revokedGrant])
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.consentDecision).toBe("revoked");
    expect(finalDecision.reason).toContain("revoked");
  });

  it("expired consent denies", () => {
    const consentRequest = request("high");
    const expiredGrant = expireConsentGrant(grantFor(consentRequest));
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [expiredGrant])
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.consentDecision).toBe("expired");
  });

  it("expiresAt before now denies", () => {
    const consentRequest = request("high");
    const expiredGrant = grantFor(consentRequest, {
      expiresAt: "2026-04-30T08:00:00.000Z"
    });
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [expiredGrant])
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.consentDecision).toBe("expired");
  });

  it("purpose mismatch denies", () => {
    const consentRequest = request("high", "read_heart_rate", "advertising");
    const wellnessGrant = grantFor(consentRequest, {
      purpose: "wellness_summary"
    });
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [wellnessGrant], "advertising")
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.consentDecision).toBe("purpose_mismatch");
  });

  it("grant for one capability does not authorize another capability", () => {
    const consentRequest = request("high", "read_sleep_summary", "wellness_summary");
    const heartRateGrant = grantFor(consentRequest, {
      capabilityId: "read_heart_rate"
    });
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [heartRateGrant])
    );

    expect(finalDecision.mode).toBe("requiresApproval");
    expect(finalDecision.consentDecision).toBe("missing");
  });

  it("grant for one app does not authorize another app", () => {
    const consentRequest = request("high");
    const otherAppGrant = grantFor(consentRequest, {
      appId: "app-other"
    });
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [otherAppGrant])
    );

    expect(finalDecision.mode).toBe("requiresApproval");
    expect(finalDecision.consentDecision).toBe("missing");
  });

  it("grant for one subject does not authorize another subject", () => {
    const consentRequest = request("high");
    const otherSubjectGrant = grantFor(consentRequest, {
      subjectId: "other-simulated-human"
    });
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [otherSubjectGrant])
    );

    expect(finalDecision.mode).toBe("requiresApproval");
    expect(finalDecision.consentDecision).toBe("missing");
  });

  it("read_battery can continue without consent", () => {
    const consentRequest = request("low", "read_battery", "device_maintenance");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [])
    );

    expect(finalDecision.mode).toBe("allowed");
    expect(finalDecision.consentDecision).toBe(
      "capability_does_not_require_consent"
    );
  });

  it("unknown capability denies fail-closed", () => {
    const consentRequest = request("low", "unknown_capability", "wellness_summary");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "low" }),
      sandbox: {
        mode: "allowed",
        reason: "Low-risk simulated request was allowed.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [])
    );

    expect(finalDecision.mode).toBe("denied");
    expect(finalDecision.consentDecision).toBe("unknown_capability");
    expect(finalDecision.reason).toContain("fail-closed");
  });

  it("consent metadata appears in final decision", () => {
    const consentRequest = request("high");
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(
      consentRequest,
      consentOptions(consentRequest, [grantFor(consentRequest)])
    );

    expect(finalDecision.consentDecision).toBe("valid");
    expect(finalDecision.consentValid).toBe(true);
    expect(finalDecision.consentReason).toEqual(expect.any(String));
    expect(finalDecision.consentSummary).toEqual(expect.any(String));
  });
});

