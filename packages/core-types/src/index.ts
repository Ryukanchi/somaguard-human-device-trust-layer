export type RiskLevel = "low" | "medium" | "high" | "critical";

export type SafetyMode =
  | "observe_only"
  | "strict"
  | "human_confirmation_required"
  | "supervised_simulation"
  | "emergency_locked";

export type AccessType =
  | "read_status"
  | "read_sensor"
  | "display_overlay"
  | "adjust_feedback"
  | "motor_assist"
  | "audit_read";

export interface DeviceCapability {
  id: string;
  name: string;
  accessType: AccessType;
  riskLevel: RiskLevel;
  description: string;
  simulationOnly: true;
}

export interface Device {
  id: string;
  name: string;
  type: "wearable_sim" | "ar_sim" | "assistive_motion_sim" | "biosensor_sim";
  safetyMode: SafetyMode;
  capabilities: DeviceCapability[];
  simulationOnly: true;
}

export interface AppIdentity {
  id: string;
  name: string;
  trustLevel: "trusted" | "semi_trusted" | "untrusted";
  trusted: boolean;
  declaredPurpose: string;
  simulationOnly: true;
}

export interface PermissionRequest {
  id: string;
  appId: string;
  deviceId: string;
  capabilityId: string;
  app: AppIdentity;
  device: Device;
  capability: DeviceCapability;
  requestedAccessType: AccessType;
  purpose: string;
  createdAt: string;
  simulationOnly: true;
}

export interface PolicyDecision {
  requestId: string;
  decision: "allow" | "deny";
  riskLevel: RiskLevel;
  reason: string;
  requiresApproval: boolean;
  audit: boolean;
  humanReadableSummary: string;
  simulationOnly: true;
}

export interface AuditEvent {
  id: string;
  eventType: "policy_decision_recorded";
  timestamp: string;
  appId: string;
  deviceId: string;
  capabilityId: string;
  capabilityName: string;
  decision: PolicyDecision["decision"];
  riskLevel: RiskLevel;
  reason: string;
  requiresApproval: boolean;
  audit: boolean;
  humanReadableSummary: string;
  simulationOnly: true;
}

export const riskLevels: readonly RiskLevel[] = [
  "low",
  "medium",
  "high",
  "critical"
];

export const safetyModes: readonly SafetyMode[] = [
  "observe_only",
  "strict",
  "human_confirmation_required",
  "supervised_simulation",
  "emergency_locked"
];
