class AuditLog {
  constructor() {
    this.events = [];
  }

  record(event) {
    this.events.push({ ...event });
  }

  getAll() {
    return this.events.map((event) => ({ ...event }));
  }

  clear() {
    this.events = [];
  }
}

function createAuditEvent(request, decision, sequence = 0) {
  const timestamp = new Date(Date.UTC(2026, 0, 1, 0, 0, sequence)).toISOString();

  return {
    id: `audit-${request.id}-${sequence}`,
    eventType: "policy_decision_recorded",
    timestamp,
    appId: request.appId,
    deviceId: request.deviceId,
    capabilityId: request.capabilityId,
    capabilityName: request.capability.name,
    decision: decision.decision,
    riskLevel: decision.riskLevel,
    reason: decision.reason,
    requiresApproval: decision.requiresApproval,
    audit: decision.audit,
    sandboxed: false,
    humanReadableSummary: `${decision.decision.toUpperCase()} ${request.app.name} -> ${request.device.name}/${request.capability.name}: ${decision.reason}`,
    simulationOnly: true
  };
}

function logDecision(request, decision, auditLog) {
  const event = createAuditEvent(request, decision, auditLog.getAll().length);
  auditLog.record(event);
  return event;
}

function createDecisionContext(request, policyEngine, context = {}) {
  const decision = policyEngine(request, context);

  return {
    request,
    policyDecision: decision
  };
}

function evaluatePermission(request, context = {}) {
  const { app, capability, device } = request;

  if (capability.riskLevel === "critical") {
    return deny(
      request,
      "Critical capability access requires explicit human approval, so this simulation denies the request until that approval is represented.",
      true
    );
  }

  if (!app.trusted && (capability.riskLevel === "high" || capability.riskLevel === "critical")) {
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

  if (app.trusted && capability.riskLevel === "medium") {
    return allow(
      request,
      "The app is trusted, but the medium-risk capability must remain contained in simulation."
    );
  }

  const isKnown = getCapabilityById(request.capabilityId) !== undefined;
  const hasValidConsent =
    !capabilityRequiresConsent(request.capabilityId) || context.consentValid === true;
  const isTrustedSystem = context.selfTrust?.trustLevel === "trusted";

  if (isKnown && hasValidConsent && isTrustedSystem) {
    return allow(
      request,
      "Valid consent, known capability, and trusted system."
    );
  }

  return deny(request, "No allow rule matched, so the request is denied by default.");
}

function deny(request, reason, requiresApproval = false) {
  return {
    requestId: request.id,
    decision: "deny",
    riskLevel: request.capability.riskLevel,
    reason,
    requiresApproval,
    audit: true,
    humanReadableSummary: `Denied ${request.app.name} access to ${request.capability.name} on ${request.device.name}: ${reason}`,
    simulationOnly: true
  };
}

function allow(request, reason) {
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

class Guardian {
  constructor(auditLog) {
    this.auditLog = auditLog;
  }

  analyze() {
    const events = this.auditLog.getAll();

    for (let index = 1; index < events.length; index += 1) {
      const previous = events[index - 1];
      const current = events[index];
      if (previous.riskLevel === "low" && (current.riskLevel === "medium" || current.riskLevel === "high")) {
        return {
          flagged: true,
          reason: "Risk escalation detected: audit history moves from low risk to medium or high risk in a short sequence."
        };
      }
    }

    let repeated = 0;
    for (const event of events) {
      if (event.riskLevel === "medium" || event.riskLevel === "high") {
        repeated += 1;
        if (repeated >= 3) {
          return {
            flagged: true,
            reason: "Repeated medium/high actions detected: three or more medium or high risk events occurred in a row."
          };
        }
      } else {
        repeated = 0;
      }
    }

    if (events.some((event) => event.riskLevel === "critical")) {
      return {
        flagged: true,
        reason: "Critical request presence detected: audit history includes a critical capability request."
      };
    }

    const deniedHighRisk = events.filter((event) => event.decision === "deny" && event.riskLevel === "high");
    if (deniedHighRisk.length >= 2) {
      return {
        flagged: true,
        reason: "Suspicious denial pattern detected: multiple denied high-risk attempts appear in the audit history."
      };
    }

    return {
      flagged: false,
      reason: null
    };
  }
}

class ComposedRiskEngine {
  constructor(auditLog) {
    this.auditLog = auditLog;
  }

  evaluate() {
    const events = this.auditLog.getAll();
    const mediumCount = events.filter((event) => event.riskLevel === "medium").length;
    const highCount = events.filter((event) => event.riskLevel === "high").length;
    const hasCritical = events.some((event) => event.riskLevel === "critical");

    if (hasCritical) {
      return {
        riskLevel: "critical",
        reason: "Composed risk is critical because at least one critical event is present."
      };
    }

    if (highCount >= 2) {
      return {
        riskLevel: "critical",
        reason: "Composed risk escalated to critical because multiple high-risk events are present."
      };
    }

    if ((mediumCount >= 1 && highCount >= 1) || mediumCount >= 2) {
      return {
        riskLevel: "high",
        reason: "Composed risk escalated to high because multiple non-low-risk events are present."
      };
    }

    if (mediumCount === 1 || highCount === 1) {
      const riskLevel = highCount === 1 ? "high" : "medium";
      return {
        riskLevel,
        reason: `Composed risk remains ${riskLevel} because only one ${riskLevel}-risk event is present.`
      };
    }

    return {
      riskLevel: "low",
      reason: "Composed risk is low because only low-risk events are present."
    };
  }
}

class SandboxEngine {
  constructor(auditLog) {
    this.auditLog = auditLog;
  }

  execute(context) {
    const { request, policyDecision: decision } = context;
    const mode = decision.decision === "deny" ? "denied" : decision.riskLevel === "low" ? "allowed" : "sandboxed";
    const event = createAuditEvent(request, decision, this.auditLog.getAll().length);
    event.sandboxed = mode === "sandboxed";
    if (event.sandboxed) {
      event.humanReadableSummary += " Execution was contained in the SomaGuard simulation sandbox.";
    }
    this.auditLog.record(event);

    if (mode === "allowed") {
      return {
        mode,
        reason: "Low-risk simulated request was allowed by policy and recorded in the audit log.",
        simulated: true
      };
    }

    if (mode === "sandboxed") {
      return {
        mode,
        reason: "Policy allowed the request, but medium or high risk requires simulated sandbox containment instead of real execution.",
        simulated: true
      };
    }

    return {
      mode,
      reason: `Request denied by policy: ${decision.reason}`,
      simulated: true
    };
  }
}

class Orchestrator {
  constructor(policyEngine, sandboxEngine, guardian, composedRisk, selfTrustResult = {
    trustLevel: "degraded",
    reason: "Self-trust result was not provided."
  }) {
    this.policyEngine = policyEngine;
    this.sandboxEngine = sandboxEngine;
    this.guardian = guardian;
    this.composedRisk = composedRisk;
    this.selfTrustResult = selfTrustResult;
  }

  handle(request, options = {}) {
    if (this.selfTrustResult.trustLevel === "compromised") {
      return withoutConsent({
        mode: "denied",
        reason: `System self-trust is compromised, so SomaGuard denies the request before other decisions: ${this.selfTrustResult.reason}`
      });
    }

    const consentResult = evaluateConsent(createConsentInput(request, options.consent));

    if (consentResult.decision === "unknown_capability") {
      return withConsent({
        mode: "denied",
        reason: `Consent denied unknown capability using fail-closed behavior: ${consentResult.reason}`
      }, consentResult);
    }

    if (consentResult.decision === "missing") {
      return withConsent({
        mode: "requiresApproval",
        reason: `Consent is missing for this simulated capability request: ${consentResult.reason}`
      }, consentResult);
    }

    if (consentResult.decision === "revoked") {
      return withConsent({
        mode: "denied",
        reason: `Consent was revoked for this simulated capability request: ${consentResult.reason}`
      }, consentResult);
    }

    if (consentResult.decision === "expired") {
      return withConsent({
        mode: "denied",
        reason: `Consent expired for this simulated capability request: ${consentResult.reason}`
      }, consentResult);
    }

    if (consentResult.decision === "purpose_mismatch") {
      return withConsent({
        mode: "denied",
        reason: `Consent purpose mismatch blocked this simulated request: ${consentResult.reason}`
      }, consentResult);
    }

    const context = createDecisionContext(request, this.policyEngine, {
      consentValid: consentResult.valid,
      selfTrust: this.selfTrustResult
    });
    const { policyDecision } = context;

    const sandboxDecision = this.sandboxEngine.execute(context);
    const guardianResult = this.guardian.analyze();
    const composedRiskResult = this.composedRisk.evaluate();

    if (policyDecision.decision === "deny") {
      return withConsent({
        mode: "denied",
        reason: `Policy denied the request: ${policyDecision.reason}`
      }, consentResult);
    }

    if (this.selfTrustResult.trustLevel === "degraded" && policyDecision.riskLevel !== "low") {
      return withConsent({
        mode: "sandboxed",
        reason: `System self-trust is degraded, so non-low-risk requests cannot be fully allowed: ${this.selfTrustResult.reason}`
      }, consentResult);
    }

    if (composedRiskResult.riskLevel === "critical") {
      return withConsent({
        mode: "requiresApproval",
        reason: `Composed risk requires explicit approval: ${composedRiskResult.reason}`
      }, consentResult);
    }

    if (guardianResult.flagged) {
      return withConsent({
        mode: "sandboxed",
        reason: `Guardian flagged the request history, so execution is contained: ${guardianResult.reason}`
      }, consentResult);
    }

    if (sandboxDecision.mode === "sandboxed") {
      return withConsent({
        mode: "sandboxed",
        reason: `Sandbox containment selected: ${sandboxDecision.reason}`
      }, consentResult);
    }

    return withConsent({
      mode: "allowed",
      reason: "Policy allowed the request, consent gate passed, Guardian did not flag history, composed risk is not critical, and sandbox did not require containment."
    }, consentResult);
  }
}

function createConsentInput(request, consentOptions = {}) {
  return {
    subjectId: consentOptions.subjectId ?? "simulated-human",
    appId: request.appId,
    capabilityId: request.capabilityId,
    purpose: consentOptions.purpose ?? request.purpose,
    now: consentOptions.now ?? request.createdAt,
    grants: consentOptions.consentGrants ?? []
  };
}

function withConsent(decision, consentResult) {
  return {
    ...decision,
    consentDecision: consentResult.decision,
    consentValid: consentResult.valid,
    consentReason: consentResult.reason,
    consentSummary: consentResult.humanReadableSummary
  };
}

function withoutConsent(decision) {
  return {
    ...decision,
    consentDecision: null,
    consentValid: null,
    consentReason: null,
    consentSummary: null
  };
}

function evaluateSelfTrust(input) {
  if (input.integrityOk === false) {
    return {
      trustLevel: "compromised",
      reason: "System integrity check failed, so SomaGuard self-trust is compromised."
    };
  }

  const actual = new Set(input.actualComponents);
  const missingComponents = input.expectedComponents.filter((component) => !actual.has(component));

  if (missingComponents.length > 0) {
    return {
      trustLevel: "degraded",
      reason: `SomaGuard self-trust is degraded because expected components are missing: ${missingComponents.join(", ")}.`
    };
  }

  return {
    trustLevel: "trusted",
    reason: "SomaGuard self-trust is trusted because integrity is acceptable and all expected components are present."
  };
}

const registeredCapabilities = {
  read_heart_rate: {
    id: "read_heart_rate",
    displayName: "Read heart rate",
    accessType: "read",
    riskLevel: "high",
    dataSensitivity: "highly_sensitive",
    bodyImpact: "informational",
    requiresConsent: true,
    allowedPurposes: [
      "user_view",
      "wellness_summary",
      "rehab_tracking",
      "safety_monitoring",
      "research_simulation"
    ],
    retentionHint: "not_recommended",
    sourceDeviceTypes: ["wearable_health_sensor"]
  },
  read_battery: {
    id: "read_battery",
    displayName: "Read battery",
    accessType: "read",
    riskLevel: "low",
    dataSensitivity: "low",
    bodyImpact: "none",
    requiresConsent: false,
    allowedPurposes: ["device_maintenance"],
    retentionHint: "ephemeral",
    sourceDeviceTypes: ["wearable_health_sensor"]
  }
};

function getCapabilityById(capabilityId) {
  return registeredCapabilities[capabilityId];
}

function isPurposeAllowed(capabilityId, purpose) {
  const capability = getCapabilityById(capabilityId);
  return capability !== undefined && capability.allowedPurposes.includes(purpose);
}

function capabilityRequiresConsent(capabilityId) {
  const capability = getCapabilityById(capabilityId);
  return capability === undefined ? true : capability.requiresConsent;
}

function createConsentGrant(input) {
  return {
    id: [
      "consent",
      input.subjectId,
      input.appId,
      input.capabilityId,
      input.purpose,
      input.grantedAt
    ].join(":"),
    subjectId: input.subjectId,
    appId: input.appId,
    capabilityId: input.capabilityId,
    purpose: input.purpose,
    status: "active",
    grantedAt: input.grantedAt,
    expiresAt: input.expiresAt ?? null,
    revokedAt: null,
    humanReadableSummary: `Simulated consent grant for ${input.subjectId} allowing ${input.appId} to use ${input.capabilityId} for ${input.purpose}.`
  };
}

function revokeConsentGrant(grant, revokedAt) {
  return {
    ...grant,
    status: "revoked",
    revokedAt,
    humanReadableSummary: `${grant.humanReadableSummary} Revoked at ${revokedAt}.`
  };
}

function isConsentExpired(grant, now) {
  return grant.status === "expired" || (grant.expiresAt !== null && grant.expiresAt < now);
}

function findMatchingConsentGrant(input) {
  return input.grants.find(
    (grant) =>
      grant.subjectId === input.subjectId &&
      grant.appId === input.appId &&
      grant.capabilityId === input.capabilityId &&
      grant.purpose === input.purpose
  );
}

function findGrantForDifferentPurpose(input) {
  return input.grants.find(
    (grant) =>
      grant.subjectId === input.subjectId &&
      grant.appId === input.appId &&
      grant.capabilityId === input.capabilityId &&
      grant.purpose !== input.purpose
  );
}

function consentResult(input) {
  return {
    ...input,
    humanReadableSummary: `${input.decision}: ${input.reason}`
  };
}

function evaluateConsent(input) {
  const capability = getCapabilityById(input.capabilityId);

  if (capability === undefined) {
    return consentResult({
      decision: "unknown_capability",
      valid: false,
      requiresConsent: true,
      matchingGrantId: null,
      capabilityId: input.capabilityId,
      purpose: input.purpose,
      reason: "Capability is not registered, so consent evaluation fails closed."
    });
  }

  const requiresConsent = capabilityRequiresConsent(input.capabilityId);

  if (!requiresConsent) {
    return consentResult({
      decision: "capability_does_not_require_consent",
      valid: true,
      requiresConsent: false,
      matchingGrantId: null,
      capabilityId: input.capabilityId,
      purpose: input.purpose,
      reason: `${input.capabilityId} does not require consent in the simulation registry.`
    });
  }

  if (!isPurposeAllowed(input.capabilityId, input.purpose)) {
    return consentResult({
      decision: "purpose_mismatch",
      valid: false,
      requiresConsent: true,
      matchingGrantId: null,
      capabilityId: input.capabilityId,
      purpose: input.purpose,
      reason: `${input.purpose} is not an allowed purpose for ${input.capabilityId}.`
    });
  }

  const matchingGrant = findMatchingConsentGrant(input);

  if (matchingGrant !== undefined) {
    if (matchingGrant.status === "revoked") {
      return consentResult({
        decision: "revoked",
        valid: false,
        requiresConsent: true,
        matchingGrantId: matchingGrant.id,
        capabilityId: input.capabilityId,
        purpose: input.purpose,
        reason: "Matching simulated consent grant has been revoked."
      });
    }

    if (isConsentExpired(matchingGrant, input.now)) {
      return consentResult({
        decision: "expired",
        valid: false,
        requiresConsent: true,
        matchingGrantId: matchingGrant.id,
        capabilityId: input.capabilityId,
        purpose: input.purpose,
        reason: "Matching simulated consent grant is expired."
      });
    }

    return consentResult({
      decision: "valid",
      valid: true,
      requiresConsent: true,
      matchingGrantId: matchingGrant.id,
      capabilityId: input.capabilityId,
      purpose: input.purpose,
      reason: "Matching active simulated consent grant is valid for this capability and purpose."
    });
  }

  const differentPurposeGrant = findGrantForDifferentPurpose(input);

  if (differentPurposeGrant !== undefined) {
    return consentResult({
      decision: "purpose_mismatch",
      valid: false,
      requiresConsent: true,
      matchingGrantId: differentPurposeGrant.id,
      capabilityId: input.capabilityId,
      purpose: input.purpose,
      reason: `A grant exists for ${input.capabilityId}, but not for requested purpose ${input.purpose}.`
    });
  }

  return consentResult({
    decision: "missing",
    valid: false,
    requiresConsent: true,
    matchingGrantId: null,
    capabilityId: input.capabilityId,
    purpose: input.purpose,
    reason: `No matching active simulated consent grant exists for ${input.capabilityId} and purpose ${input.purpose}.`
  });
}

const apps = {
  rehabAssist: {
    id: "app-rehabassist",
    name: "RehabAssist",
    trustLevel: "trusted",
    trusted: true
  },
  deviceMaintenance: {
    id: "app-device-maintenance",
    name: "DeviceMaintenance",
    trustLevel: "trusted",
    trusted: true
  },
  suspiciousOptimizer: {
    id: "app-suspiciousoptimizer",
    name: "SuspiciousOptimizer",
    trustLevel: "untrusted",
    trusted: false
  }
};

const devices = {
  pulseBand: {
    id: "device-pulseband-sim",
    name: "PulseBand Sim",
    type: "wearable_health_sensor",
    safetyMode: "observe_only"
  }
};

const capabilities = {
  heartRate: {
    id: "read_heart_rate",
    name: "Read heart rate",
    accessType: "read",
    riskLevel: "high"
  },
  battery: {
    id: "read_battery",
    name: "Read battery",
    accessType: "read",
    riskLevel: "low"
  },
  unknownSignal: {
    id: "read_unknown_signal",
    name: "Read unknown signal",
    accessType: "read",
    riskLevel: "high"
  }
};

const demoSubjectId = "simulated-human";
const demoNow = "2026-01-01T12:00:00.000Z";
const demoGrantedAt = "2026-01-01T09:00:00.000Z";
const demoExpiredAt = "2025-12-31T12:00:00.000Z";

function makeRequest(id, app, device, capability, purpose) {
  return {
    id,
    appId: app.id,
    deviceId: device.id,
    capabilityId: capability.id,
    app,
    device,
    capability,
    requestedAccessType: capability.accessType,
    purpose,
    createdAt: demoNow,
    simulationOnly: true
  };
}

const activeHeartRateGrant = createConsentGrant({
  subjectId: demoSubjectId,
  appId: apps.rehabAssist.id,
  capabilityId: "read_heart_rate",
  purpose: "wellness_summary",
  grantedAt: demoGrantedAt,
  expiresAt: "2026-01-02T12:00:00.000Z"
});

const revokedHeartRateGrant = revokeConsentGrant(
  createConsentGrant({
    subjectId: demoSubjectId,
    appId: apps.rehabAssist.id,
    capabilityId: "read_heart_rate",
    purpose: "wellness_summary",
    grantedAt: demoGrantedAt,
    expiresAt: "2026-01-02T12:00:00.000Z"
  }),
  "2026-01-01T10:00:00.000Z"
);

const expiredHeartRateGrant = createConsentGrant({
  subjectId: demoSubjectId,
  appId: apps.rehabAssist.id,
  capabilityId: "read_heart_rate",
  purpose: "wellness_summary",
  grantedAt: "2025-12-30T12:00:00.000Z",
  expiresAt: demoExpiredAt
});

const wellnessOnlyGrantForSuspiciousApp = createConsentGrant({
  subjectId: demoSubjectId,
  appId: apps.suspiciousOptimizer.id,
  capabilityId: "read_heart_rate",
  purpose: "wellness_summary",
  grantedAt: demoGrantedAt,
  expiresAt: "2026-01-02T12:00:00.000Z"
});

const scenarios = {
  "valid-consent-heart-rate": {
    id: "valid-consent-heart-rate",
    name: "Valid Consent — Heart Rate Wellness",
    summary: "RehabAssist requests a simulated PulseBand heart-rate signal for a wellness summary with an active matching consent grant.",
    consentGrants: [activeHeartRateGrant],
    steps: [
      {
        request: makeRequest("valid-consent-1", apps.rehabAssist, devices.pulseBand, capabilities.heartRate, "wellness_summary")
      }
    ]
  },
  "missing-consent-heart-rate": {
    id: "missing-consent-heart-rate",
    name: "Missing Consent — Heart Rate Wellness",
    summary: "RehabAssist requests the same simulated heart-rate capability, but no matching consent grant is present.",
    consentGrants: [],
    steps: [
      {
        request: makeRequest("missing-consent-1", apps.rehabAssist, devices.pulseBand, capabilities.heartRate, "wellness_summary")
      }
    ]
  },
  "revoked-consent": {
    id: "revoked-consent",
    name: "Revoked Consent",
    summary: "A matching consent grant exists, but it has been revoked before the request is evaluated.",
    consentGrants: [revokedHeartRateGrant],
    steps: [
      {
        request: makeRequest("revoked-consent-1", apps.rehabAssist, devices.pulseBand, capabilities.heartRate, "wellness_summary")
      }
    ]
  },
  "expired-consent": {
    id: "expired-consent",
    name: "Expired Consent",
    summary: "A matching consent grant exists, but its expiration time is before the deterministic demo time.",
    consentGrants: [expiredHeartRateGrant],
    steps: [
      {
        request: makeRequest("expired-consent-1", apps.rehabAssist, devices.pulseBand, capabilities.heartRate, "wellness_summary")
      }
    ]
  },
  "purpose-mismatch-advertising": {
    id: "purpose-mismatch-advertising",
    name: "Purpose Mismatch — Advertising Attempt",
    summary: "SuspiciousOptimizer asks for a highly sensitive simulated signal for advertising. The registry does not allow advertising for this capability.",
    consentGrants: [wellnessOnlyGrantForSuspiciousApp],
    steps: [
      {
        request: makeRequest("purpose-mismatch-1", apps.suspiciousOptimizer, devices.pulseBand, capabilities.heartRate, "advertising")
      }
    ]
  },
  "battery-diagnostics": {
    id: "battery-diagnostics",
    name: "Non-Consent Capability — Battery Diagnostics",
    summary: "DeviceMaintenance reads a low-risk simulated battery status for device maintenance. The registry marks this capability as not requiring consent.",
    consentGrants: [],
    steps: [
      {
        request: makeRequest("battery-diagnostics-1", apps.deviceMaintenance, devices.pulseBand, capabilities.battery, "device_maintenance")
      }
    ]
  },
  "unknown-capability": {
    id: "unknown-capability",
    name: "Unknown Capability — Fail Closed",
    summary: "SuspiciousOptimizer requests an unregistered simulated signal. Unknown capabilities fail closed at the consent gate.",
    consentGrants: [],
    steps: [
      {
        request: makeRequest("unknown-capability-1", apps.suspiciousOptimizer, devices.pulseBand, capabilities.unknownSignal, "wellness_summary")
      }
    ]
  }
};

const auditLog = new AuditLog();
const expectedComponents = [
  "audit-log",
  "capability-registry",
  "consent-engine",
  "decision-context",
  "policy-engine",
  "sandbox",
  "guardian",
  "composed-risk",
  "orchestrator",
  "self-trust"
];

const elements = {
  scenarioSelect: document.querySelector("#scenario-select"),
  trustSelect: document.querySelector("#trust-select"),
  runButton: document.querySelector("#run-button"),
  trustLevel: document.querySelector("#trust-level"),
  trustReason: document.querySelector("#trust-reason"),
  scenarioName: document.querySelector("#scenario-name"),
  scenarioSummary: document.querySelector("#scenario-summary"),
  requestSummary: document.querySelector("#request-summary"),
  requestDetail: document.querySelector("#request-detail"),
  consentDecision: document.querySelector("#consent-decision"),
  consentReason: document.querySelector("#consent-reason"),
  finalDecision: document.querySelector("#final-decision"),
  finalReason: document.querySelector("#final-reason"),
  guardianResult: document.querySelector("#guardian-result"),
  guardianReason: document.querySelector("#guardian-reason"),
  composedRisk: document.querySelector("#composed-risk"),
  composedReason: document.querySelector("#composed-reason"),
  auditLog: document.querySelector("#audit-log")
};

function runSelectedScenario() {
  const scenario = scenarios[elements.scenarioSelect.value];
  const selfTrustResult = evaluateSelfTrust(createSelfTrustInput(elements.trustSelect.value));
  auditLog.clear();

  const guardian = new Guardian(auditLog);
  const composedRisk = new ComposedRiskEngine(auditLog);
  const sandboxEngine = new SandboxEngine(auditLog);
  const orchestrator = new Orchestrator(evaluatePermission, sandboxEngine, guardian, composedRisk, selfTrustResult);
  const lastRequest = scenario.steps[scenario.steps.length - 1].request;
  const finalDecision = orchestrator.handle(lastRequest, {
    consent: {
      subjectId: demoSubjectId,
      purpose: lastRequest.purpose,
      now: demoNow,
      consentGrants: scenario.consentGrants
    }
  });

  const guardianResult = guardian.analyze();
  const composedRiskResult = composedRisk.evaluate();

  renderSelfTrust(selfTrustResult);
  renderResults(scenario, lastRequest, finalDecision, guardianResult, composedRiskResult);
  renderAuditLog(auditLog.getAll());
}

function createSelfTrustInput(mode) {
  if (mode === "degraded") {
    return {
      expectedComponents,
      actualComponents: expectedComponents.filter((component) => component !== "guardian"),
      integrityOk: true
    };
  }

  if (mode === "compromised") {
    return {
      expectedComponents,
      actualComponents: expectedComponents,
      integrityOk: false
    };
  }

  return {
    expectedComponents,
    actualComponents: expectedComponents,
    integrityOk: true
  };
}

function renderSelfTrust(selfTrustResult) {
  elements.trustLevel.textContent = selfTrustResult.trustLevel.toUpperCase();
  elements.trustLevel.className = `trust-${selfTrustResult.trustLevel}`;
  elements.trustReason.textContent = selfTrustResult.reason;
}

function renderResults(scenario, request, finalDecision, guardianResult, composedRiskResult) {
  elements.scenarioName.textContent = scenario.name;
  elements.scenarioSummary.textContent = scenario.summary;

  elements.requestSummary.textContent = `${request.app.name} → ${request.capability.id}`;
  elements.requestDetail.textContent = [
    `appId=${request.appId}`,
    `capability=${request.capabilityId}`,
    `purpose=${request.purpose}`,
    `risk=${request.capability.riskLevel}`
  ].join(" · ");

  const consentLabel = finalDecision.consentDecision ?? "not_evaluated";
  const consentValid = finalDecision.consentValid === null ? "unknown" : String(finalDecision.consentValid);
  elements.consentDecision.textContent = `${consentLabel} · valid=${consentValid}`;
  elements.consentDecision.className = finalDecision.consentValid ? "consent-valid" : "consent-invalid";
  elements.consentReason.textContent = finalDecision.consentSummary ?? "Consent was not evaluated because the request was stopped before the consent gate.";

  elements.finalDecision.textContent = finalDecision.mode;
  elements.finalDecision.className = `decision-${finalDecision.mode}`;
  elements.finalReason.textContent = finalDecision.reason;

  elements.guardianResult.textContent = guardianResult.flagged ? "flagged" : "clear";
  elements.guardianReason.textContent = guardianResult.reason ?? "No suspicious audit pattern detected.";

  elements.composedRisk.textContent = composedRiskResult.riskLevel;
  elements.composedRisk.className = `risk-${composedRiskResult.riskLevel}`;
  elements.composedReason.textContent = composedRiskResult.reason;
}

function renderAuditLog(events) {
  elements.auditLog.replaceChildren();

  if (events.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-log";
    empty.textContent = "No events recorded.";
    elements.auditLog.append(empty);
    return;
  }

  for (const event of events) {
    const item = document.createElement("li");
    item.innerHTML = `
      <div class="audit-line">
        <span>${event.capabilityName}</span>
        <span class="risk-${event.riskLevel}">${event.riskLevel}</span>
      </div>
      <div class="audit-meta">
        decision=<span class="decision-${event.decision === "deny" ? "denied" : "allowed"}">${event.decision}</span>
        · sandboxed=${String(event.sandboxed)}
      </div>
    `;
    elements.auditLog.append(item);
  }
}

elements.runButton.addEventListener("click", runSelectedScenario);
elements.trustSelect.addEventListener("change", runSelectedScenario);
runSelectedScenario();
