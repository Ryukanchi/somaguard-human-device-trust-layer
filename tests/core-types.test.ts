import { describe, expect, it } from "vitest";
import apps from "../examples/demo-apps.json" with { type: "json" };
import devices from "../examples/demo-devices.json" with { type: "json" };
import type { AppIdentity, Device, RiskLevel } from "../packages/core-types/src/index.js";
import { riskLevels, safetyModes } from "../packages/core-types/src/index.js";

const demoApps = apps as AppIdentity[];
const demoDevices = devices as Device[];

describe("SomaGuard core fixtures", () => {
  it("devices have valid safety modes", () => {
    for (const device of demoDevices) {
      expect(safetyModes).toContain(device.safetyMode);
      expect(device.simulationOnly).toBe(true);
    }
  });

  it("AssistArm contains a high or critical motor-assist capability", () => {
    const assistArm = demoDevices.find((device) => device.name === "AssistArm Sim");

    expect(assistArm).toBeDefined();
    expect(
      assistArm?.capabilities.some(
        (capability) =>
          capability.accessType === "motor_assist" &&
          (capability.riskLevel === "high" || capability.riskLevel === "critical")
      )
    ).toBe(true);
  });

  it("SuspiciousOptimizer is not trusted", () => {
    const suspiciousOptimizer = demoApps.find(
      (app) => app.name === "SuspiciousOptimizer"
    );

    expect(suspiciousOptimizer).toBeDefined();
    expect(suspiciousOptimizer?.trusted).toBe(false);
    expect(suspiciousOptimizer?.trustLevel).toBe("untrusted");
  });

  it("all capabilities include a risk level", () => {
    for (const device of demoDevices) {
      for (const capability of device.capabilities) {
        expect(capability.riskLevel).toEqual(expect.any(String));
        expect(riskLevels).toContain(capability.riskLevel as RiskLevel);
      }
    }
  });
});

