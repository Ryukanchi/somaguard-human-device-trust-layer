export type RiskLevel = "low" | "medium" | "high" | "critical";

export type SafetyMode =
  | "observe_only"
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
  requestedAccessType: AccessType;
  purpose: string;
  createdAt: string;
  simulationOnly: true;
}

export interface PolicyDecision {
  id: string;
  requestId: string;
  outcome: "allow" | "deny" | "requires_confirmation";
  riskLevel: RiskLevel;
  reason: string;
  humanReadableSummary: string;
  createdAt: string;
  simulationOnly: true;
}

export interface AuditEvent {
  id: string;
  eventType:
    | "permission_requested"
    | "permission_decided"
    | "safety_mode_changed"
    | "emergency_lock_triggered";
  actorId: string;
  targetId: string;
  summary: string;
  createdAt: string;
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
  "human_confirmation_required",
  "supervised_simulation",
  "emergency_locked"
];

