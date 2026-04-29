import type {
  AuditEvent,
  PermissionRequest,
  PolicyDecision
} from "../../core-types/src/index.js";

const baseTimestampMs = Date.UTC(2026, 0, 1, 0, 0, 0, 0);

export class AuditLog {
  private events: AuditEvent[] = [];

  record(event: AuditEvent): void {
    this.events.push({ ...event });
  }

  getAll(): AuditEvent[] {
    return this.events.map((event) => ({ ...event }));
  }

  clear(): void {
    this.events = [];
  }
}

export function createAuditEvent(
  request: PermissionRequest,
  decision: PolicyDecision,
  sequence = 0
): AuditEvent {
  const timestamp = new Date(baseTimestampMs + sequence * 1000).toISOString();

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
    humanReadableSummary: `${decision.decision.toUpperCase()} ${request.app.name} -> ${request.device.name}/${request.capability.name}: ${decision.reason}`,
    simulationOnly: true
  };
}

export function logDecision(
  request: PermissionRequest,
  decision: PolicyDecision,
  auditLog: AuditLog
): AuditEvent {
  const event = createAuditEvent(request, decision, auditLog.getAll().length);
  auditLog.record(event);
  return event;
}

