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

function createDecisionContext(request, policyEngine) {
  const decision = policyEngine(request);

  return {
    request,
    policyDecision: decision
  };
}

function evaluatePermission(request) {
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

class ScenarioEngine {
  constructor(policyEngine, auditLog) {
    this.policyEngine = policyEngine;
    this.auditLog = auditLog;
  }

  runScenario(scenario) {
    const decisions = [];
    const auditEvents = [];

    for (const step of scenario.steps) {
      const decision = this.policyEngine(step.request);
      const event = logDecision(step.request, decision, this.auditLog);
      decisions.push(decision);
      auditEvents.push(event);
    }

    const flagReason = detectScenarioFlag(scenario, decisions);

    return {
      decisions,
      auditEvents,
      flagged: flagReason !== null,
      flagReason
    };
  }
}

function detectScenarioFlag(scenario, decisions) {
  if (scenario.steps.some((step) => step.request.capability.riskLevel === "critical")) {
    return "critical interaction detected: scenario includes a critical capability request.";
  }

  if (decisions.some((decision) => decision.decision === "deny" && decision.riskLevel === "high")) {
    return "blocked high-risk attempt: at least one high-risk request was denied.";
  }

  let consecutive = 0;
  for (const decision of decisions) {
    if (decision.riskLevel === "medium" || decision.riskLevel === "high") {
      consecutive += 1;
      if (consecutive >= 2) {
        return "risk accumulation: multiple medium or high risk actions occurred in sequence.";
      }
    } else {
      consecutive = 0;
    }
  }

  return null;
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

  handle(request) {
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

    if (this.selfTrustResult.trustLevel === "degraded" && policyDecision.riskLevel !== "low") {
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
      reason: "Policy allowed the request, Guardian did not flag history, composed risk is not critical, and sandbox did not require containment."
    };
  }
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

const apps = {
  rehabAssist: {
    id: "app-rehabassist",
    name: "RehabAssist",
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
    safetyMode: "observe_only"
  },
  assistArm: {
    id: "device-assistarm-sim",
    name: "AssistArm Sim",
    safetyMode: "observe_only"
  }
};

const capabilities = {
  status: {
    id: "pulseband-status-read",
    name: "Read simulated status",
    accessType: "read_status",
    riskLevel: "low"
  },
  sensor: {
    id: "pulseband-sensor-read",
    name: "Read synthetic signal",
    accessType: "read_sensor",
    riskLevel: "medium"
  },
  assist: {
    id: "assistarm-motor-assist",
    name: "Request simulated motor assist",
    accessType: "motor_assist",
    riskLevel: "critical"
  }
};

function makeRequest(id, app, device, capability) {
  return {
    id,
    appId: app.id,
    deviceId: device.id,
    capabilityId: capability.id,
    app,
    device,
    capability,
    requestedAccessType: capability.accessType,
    purpose: "SomaGuard browser demo.",
    createdAt: "2026-04-29T00:00:00.000Z",
    simulationOnly: true
  };
}

const scenarios = {
  "safe-flow": {
    id: "safe-flow",
    name: "Safe Flow",
    steps: [
      {
        request: makeRequest("safe-1", apps.rehabAssist, devices.pulseBand, capabilities.status)
      },
      {
        request: makeRequest("safe-2", apps.rehabAssist, devices.pulseBand, capabilities.status)
      }
    ]
  },
  "risk-accumulation": {
    id: "risk-accumulation",
    name: "Risk Accumulation",
    steps: [
      {
        request: makeRequest("risk-1", apps.rehabAssist, devices.pulseBand, capabilities.status)
      },
      {
        request: makeRequest("risk-2", apps.rehabAssist, devices.pulseBand, capabilities.sensor)
      },
      {
        request: makeRequest("risk-3", apps.rehabAssist, devices.pulseBand, capabilities.sensor)
      }
    ]
  },
  "critical-attempt": {
    id: "critical-attempt",
    name: "Critical Attempt",
    steps: [
      {
        request: makeRequest("critical-1", apps.suspiciousOptimizer, devices.assistArm, capabilities.assist)
      }
    ]
  }
};

const auditLog = new AuditLog();
const expectedComponents = [
  "policy-engine",
  "sandbox",
  "guardian",
  "composed-risk",
  "orchestrator"
];

const elements = {
  scenarioSelect: document.querySelector("#scenario-select"),
  trustSelect: document.querySelector("#trust-select"),
  runButton: document.querySelector("#run-button"),
  trustLevel: document.querySelector("#trust-level"),
  trustReason: document.querySelector("#trust-reason"),
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

  const scenarioEngine = new ScenarioEngine(evaluatePermission, auditLog);
  scenarioEngine.runScenario(scenario);

  const guardian = new Guardian(auditLog);
  const composedRisk = new ComposedRiskEngine(auditLog);
  const sandboxLog = new AuditLog();
  const sandboxEngine = new SandboxEngine(sandboxLog);
  const orchestrator = new Orchestrator(evaluatePermission, sandboxEngine, guardian, composedRisk, selfTrustResult);
  const lastRequest = scenario.steps[scenario.steps.length - 1].request;
  const finalDecision = orchestrator.handle(lastRequest);

  const guardianResult = guardian.analyze();
  const composedRiskResult = composedRisk.evaluate();

  renderSelfTrust(selfTrustResult);
  renderResults(finalDecision, guardianResult, composedRiskResult);
  renderAuditLog(auditLog.getAll().concat(sandboxLog.getAll()));
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

function renderResults(finalDecision, guardianResult, composedRiskResult) {
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
