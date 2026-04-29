import { describe, expect, it } from "vitest";
import { AuditLog } from "../packages/audit-log/src/index.js";
import type {
  AppIdentity,
  Device,
  DeviceCapability,
  PermissionRequest
} from "../packages/core-types/src/index.js";
import { evaluatePermission } from "../packages/policy-engine/src/index.js";
import {
  ScenarioEngine,
  type Scenario
} from "../packages/scenario-engine/src/index.js";

const trustedApp: AppIdentity = {
  id: "app-trusted",
  name: "Trusted App",
  trustLevel: "trusted",
  trusted: true,
  declaredPurpose: "Trusted scenario simulation app.",
  simulationOnly: true
};

const untrustedApp: AppIdentity = {
  id: "app-untrusted",
  name: "Untrusted App",
  trustLevel: "untrusted",
  trusted: false,
  declaredPurpose: "Untrusted scenario simulation app.",
  simulationOnly: true
};

const device: Device = {
  id: "device-sim",
  name: "Scenario Device Sim",
  type: "wearable_sim",
  safetyMode: "observe_only",
  capabilities: [],
  simulationOnly: true
};

const lowCapability: DeviceCapability = {
  id: "cap-low",
  name: "Read simulated status",
  accessType: "read_status",
  riskLevel: "low",
  description: "Reads synthetic status only.",
  simulationOnly: true
};

const mediumCapability: DeviceCapability = {
  id: "cap-medium",
  name: "Read simulated sensor",
  accessType: "read_sensor",
  riskLevel: "medium",
  description: "Reads synthetic sensor data only.",
  simulationOnly: true
};

const highCapability: DeviceCapability = {
  id: "cap-high",
  name: "Display high-risk simulated overlay",
  accessType: "display_overlay",
  riskLevel: "high",
  description: "Displays a high-risk simulated overlay.",
  simulationOnly: true
};

const criticalCapability: DeviceCapability = {
  id: "cap-critical",
  name: "Request simulated motor assist",
  accessType: "motor_assist",
  riskLevel: "critical",
  description: "Represents simulated motor assist with no hardware interaction.",
  simulationOnly: true
};

function makeRequest(input: {
  id: string;
  app: AppIdentity;
  capability: DeviceCapability;
}): PermissionRequest {
  return {
    id: input.id,
    appId: input.app.id,
    deviceId: device.id,
    capabilityId: input.capability.id,
    app: input.app,
    device,
    capability: input.capability,
    requestedAccessType: input.capability.accessType,
    purpose: "Scenario engine test.",
    createdAt: "2026-04-29T00:00:00.000Z",
    simulationOnly: true
  };
}

function runScenario(scenario: Scenario) {
  const auditLog = new AuditLog();
  const engine = new ScenarioEngine(evaluatePermission, auditLog);

  return {
    result: engine.runScenario(scenario),
    auditLog
  };
}

describe("ScenarioEngine", () => {
  it("does not flag a safe low-risk scenario", () => {
    const { result, auditLog } = runScenario({
      id: "scenario-safe",
      name: "Safe low-risk scenario",
      steps: [
        {
          request: makeRequest({
            id: "request-safe-1",
            app: trustedApp,
            capability: lowCapability
          })
        }
      ]
    });

    expect(result.flagged).toBe(false);
    expect(result.flagReason).toBeNull();
    expect(result.decisions).toHaveLength(1);
    expect(result.auditEvents).toEqual(auditLog.getAll());
  });

  it("flags risk accumulation from multiple medium or high actions in sequence", () => {
    const { result } = runScenario({
      id: "scenario-risk-accumulation",
      name: "Risk accumulation scenario",
      steps: [
        {
          request: makeRequest({
            id: "request-risk-1",
            app: trustedApp,
            capability: mediumCapability
          })
        },
        {
          request: makeRequest({
            id: "request-risk-2",
            app: trustedApp,
            capability: mediumCapability
          })
        }
      ]
    });

    expect(result.flagged).toBe(true);
    expect(result.flagReason).toContain("risk accumulation");
  });

  it("flags a denied high-risk attempt", () => {
    const { result } = runScenario({
      id: "scenario-high-denied",
      name: "High-risk denied scenario",
      steps: [
        {
          request: makeRequest({
            id: "request-high-denied",
            app: untrustedApp,
            capability: highCapability
          })
        }
      ]
    });

    expect(result.flagged).toBe(true);
    expect(result.flagReason).toContain("blocked high-risk attempt");
    expect(result.decisions[0]?.decision).toBe("deny");
  });

  it("flags critical capability requests", () => {
    const { result } = runScenario({
      id: "scenario-critical",
      name: "Critical capability scenario",
      steps: [
        {
          request: makeRequest({
            id: "request-critical",
            app: trustedApp,
            capability: criticalCapability
          })
        }
      ]
    });

    expect(result.flagged).toBe(true);
    expect(result.flagReason).toContain("critical interaction detected");
    expect(result.decisions[0]?.requiresApproval).toBe(true);
  });
});

