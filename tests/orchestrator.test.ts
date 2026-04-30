import { describe, expect, it } from "vitest";
import type {
  AppIdentity,
  Device,
  DeviceCapability,
  PermissionRequest,
  PolicyDecision,
  RiskLevel
} from "../packages/core-types/src/index.js";
import { Orchestrator } from "../packages/orchestrator/src/index.js";
import type { SandboxResult } from "../packages/sandbox/src/index.js";
import type { GuardianResult } from "../packages/guardian/src/index.js";
import type { ComposedRiskResult } from "../packages/composed-risk/src/index.js";
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

function capability(riskLevel: RiskLevel): DeviceCapability {
  return {
    id: `cap-${riskLevel}`,
    name: `${riskLevel} capability`,
    accessType: "read_status",
    riskLevel,
    description: "Test capability.",
    simulationOnly: true
  };
}

function request(riskLevel: RiskLevel): PermissionRequest {
  const selectedCapability = capability(riskLevel);

  return {
    id: `request-${riskLevel}`,
    appId: app.id,
    deviceId: device.id,
    capabilityId: selectedCapability.id,
    app,
    device,
    capability: selectedCapability,
    requestedAccessType: selectedCapability.accessType,
    purpose: "Orchestrator test.",
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
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "medium" }),
      sandbox: {
        mode: "sandboxed",
        reason: "Medium-risk simulated request requires containment.",
        simulated: true
      },
      selfTrustResult: trustedSelfTrust
    });

    const finalDecision = orchestrator.handle(request("medium"));

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

    const finalDecision = orchestrator.handle(request("high"));

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

    const finalDecision = orchestrator.handle(request("high"));

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
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "medium" }),
      sandbox: {
        mode: "sandboxed",
        reason: "Medium-risk simulated request requires containment.",
        simulated: true
      }
    });

    const finalDecision = orchestrator.handle(request("medium"));

    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("Self-trust result was not provided.");
  });

  it("missing selfTrustResult does not fully allow high-risk requests", () => {
    const orchestrator = buildOrchestrator({
      policy: policyDecision({ decision: "allow", riskLevel: "high" }),
      sandbox: {
        mode: "sandboxed",
        reason: "High-risk simulated request requires containment.",
        simulated: true
      }
    });

    const finalDecision = orchestrator.handle(request("high"));

    expect(finalDecision.mode).not.toBe("allowed");
    expect(finalDecision.mode).toBe("sandboxed");
    expect(finalDecision.reason).toContain("self-trust is degraded");
  });
});
