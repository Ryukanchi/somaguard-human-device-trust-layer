import type {
  PermissionRequest,
  PolicyDecision,
  RiskLevel
} from "../../core-types/src/index.js";
import {
  isKnownCapability,
  requiresConsent
} from "../../capability-registry/src/index.js";
import type { PolicyEvaluationContext } from "../../decision-context/src/index.js";

function isHighOrCritical(riskLevel: RiskLevel): boolean {
  return riskLevel === "high" || riskLevel === "critical";
}

function deny(
  request: PermissionRequest,
  reason: string,
  requiresApproval = false,
  audit = true
): PolicyDecision {
  return {
    requestId: request.id,
    decision: "deny",
    riskLevel: request.capability.riskLevel,
    reason,
    requiresApproval,
    audit,
    humanReadableSummary: `Denied ${request.app.name} access to ${request.capability.name} on ${request.device.name}: ${reason}`,
    simulationOnly: true
  };
}

function allow(request: PermissionRequest, reason: string): PolicyDecision {
  return {
    requestId: request.id,
    decision: "allow",
    riskLevel: request.capability.riskLevel,
    reason,
    requiresApproval: false,
    audit: true,
    humanReadableSummary: `Allowed ${request.app.name} access to ${request.capability.name} on ${request.device.name}: ${reason}`,
    simulationOnly: true
  };
}

export function evaluatePermission(
  request: PermissionRequest,
  context: PolicyEvaluationContext = {}
): PolicyDecision {
  const { app, capability, device } = request;

  if (capability.riskLevel === "critical") {
    return deny(
      request,
      "Critical capability access requires explicit human approval, so this simulation denies the request until that approval is represented.",
      true
    );
  }

  if (!app.trusted && isHighOrCritical(capability.riskLevel)) {
    return deny(
      request,
      `The requesting app trust level is ${app.trustLevel}, and the requested capability risk level is ${capability.riskLevel}.`
    );
  }

  if (device.safetyMode === "strict" && capability.riskLevel !== "low") {
    return deny(
      request,
      "The target device is in strict safety mode, so non-low-risk capabilities are blocked."
    );
  }

  if (app.trusted && capability.riskLevel === "low") {
    return allow(
      request,
      "The app is trusted and the requested simulated capability is low risk."
    );
  }

  const isKnown = isKnownCapability(request.capabilityId);
  const hasValidConsent =
    !requiresConsent(request.capabilityId) || context.consentValid === true;
  const isTrustedSystem = context.selfTrust?.trustLevel === "trusted";

  if (isKnown && hasValidConsent && isTrustedSystem) {
    return allow(
      request,
      "Valid consent, known capability, and trusted system."
    );
  }

  return deny(
    request,
    "No allow rule matched, so the request is denied by default."
  );
}
