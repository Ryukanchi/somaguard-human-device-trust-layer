# Capability Registry v1

This document defines the purpose, scope, and safety boundaries for SomaGuard's planned Capability Registry v1.

The first concrete anchor is **PulseBand Sim**, a fictional, simulated wearable health sensor model inspired by permission concepts found in platforms such as HealthKit and Google Health Connect.

This is not a HealthKit integration. This is not a Google Health Connect integration. SomaGuard remains simulation-only.

## Purpose

The Capability Registry will define the actions and data access surfaces that simulated devices can expose. It gives SomaGuard a concrete vocabulary for future consent, policy, audit, and scenario work.

Without a registry, a permission request is too abstract. A request such as "read data" does not explain what kind of data is involved, why it is sensitive, what purpose is allowed, or how long the data should exist.

The registry is intended to answer questions such as:

- What capability is being requested?
- What simulated device type exposes it?
- How sensitive is the data?
- Does it require consent?
- What purposes are appropriate?
- What retention expectations apply?
- Does the capability imply any body impact?

## Capability

A capability is a named, registry-defined action or data access surface that a simulated device can expose.

Examples:

- `read_heart_rate`
- `read_motion`
- `read_temperature`
- `read_sleep_summary`
- `read_location_context`
- `read_device_diagnostics`

Capabilities should be stable identifiers. Future policy and consent decisions should refer to capability IDs rather than vague labels.

## Why SomaGuard Needs A Registry

SomaGuard currently has decision layers, audit layers, scenario execution, sandboxing, self-trust, and composed risk analysis. Those layers need concrete capability metadata to become meaningful.

A registry helps prevent every layer from inventing its own interpretation of risk. It also provides a shared source of truth for future consent and privacy reasoning.

The registry supports:

- **Consent Engine:** Consent can be scoped to specific capabilities and purposes instead of broad yes/no approval.
- **Policy Engine:** Policy can evaluate sensitivity, body impact, purpose, and consent requirements instead of only a generic risk level.
- **Audit Log:** Audit records can preserve which registered capability was requested and why it mattered.
- **Scenario Engine:** Scenarios can use realistic, repeatable simulated capabilities.
- **GDPR-style privacy reasoning:** The registry can identify data sensitivity, purpose binding, and retention expectations without claiming regulatory compliance.

## Why A Wearable Health Sensor Anchor

The first anchor should be concrete, familiar, and privacy-relevant. A simulated wearable health sensor is a practical starting point because it involves sensitive body-adjacent data without requiring real hardware, medical claims, or actuation.

PulseBand Sim creates a grounded model for:

- body-adjacent data access
- consent requirements
- purpose limitation
- retention hints
- auditability
- scenario design

It is intentionally less speculative than cyberware, implants, prosthetics, or exoskeleton control.

## PulseBand Sim

PulseBand Sim is:

- fictional
- simulated
- wearable-health-sensor-like
- local only
- based on synthetic data concepts
- intended for permission and trust-layer modeling

PulseBand Sim is not:

- a real wearable
- a medical device
- a diagnostic system
- a treatment system
- an emergency alerting system
- a HealthKit integration
- a Google Health Connect integration
- a hardware driver

PulseBand Sim must not ingest real biometric data.

## Initial Planned Capabilities

Capability Registry v1 should define these initial PulseBand Sim capabilities:

- `read_heart_rate`
- `read_motion`
- `read_temperature`
- `read_battery`
- `read_sleep_summary`
- `read_location_context`
- `read_stress_signal`
- `read_device_diagnostics`

These capabilities are for simulation and trust modeling only.

## Planned Capability Metadata

Each registered capability should later include:

- `id`: stable machine-readable capability identifier
- `displayName`: human-readable label
- `description`: plain-language explanation
- `accessType`: the kind of simulated access requested
- `riskLevel`: baseline risk level
- `dataSensitivity`: privacy sensitivity category
- `bodyImpact`: whether the capability affects the body or only describes data
- `requiresConsent`: whether explicit consent is required
- `allowedPurposes`: purposes that can justify access
- `retentionHint`: expected data retention boundary
- `sourceDeviceTypes`: simulated device types that can expose the capability

This metadata is not a substitute for policy or consent. It is the shared vocabulary those future systems should use.

## Data Sensitivity

Body-adjacent data should not be treated as automatically low risk. Even read-only simulated signals may be sensitive depending on what they represent and how they are combined.

Planned sensitivity categories:

- `low`: low sensitivity operational data, such as battery status
- `moderate`: data that may reveal behavior or device usage patterns
- `sensitive`: body-adjacent or wellness-like data
- `highly_sensitive`: data that may reveal intimate context, location context, or aggregated body-adjacent patterns

For v1, heart rate, sleep summary, stress signal, temperature, and location context should not be classified as low sensitivity.

## Body Impact

Body impact describes whether a capability merely reads or describes simulated data, or whether it could affect a human-adjacent experience.

Planned body impact categories:

- `none`: no body-adjacent effect
- `informational`: presents or reads information only
- `perceptual`: affects simulated perception or display context
- `assistive`: relates to simulated assistance
- `actuation`: controls simulated movement or physical effect

For Capability Registry v1, PulseBand Sim should stay mostly `none` or `informational`. Actuation and motor control are out of scope.

## Purpose Binding

Future consent must be tied to purpose. A yes/no checkbox is not enough for body-adjacent data.

Examples of allowed purposes:

- `wellness_summary`
- `rehab_tracking`
- `safety_monitoring`
- `device_maintenance`
- `research_simulation`

A capability may be acceptable for one purpose and inappropriate for another. For example, reading simulated battery status for device maintenance is different from reading simulated location context for behavioral profiling.

## Retention Hint

A retention hint describes how long data from a capability should exist in future implementations.

Planned retention hints:

- `ephemeral`: use only for immediate decision-making
- `session_only`: retain only during the current simulated session
- `short_term`: retain briefly for review or audit support
- `not_recommended`: retention should generally be avoided

Retention hints do not implement storage rules. They guide future consent, policy, and audit design.

## Explicitly Out Of Scope

Capability Registry v1 does not include:

- real health data
- real medical device support
- diagnosis
- treatment advice
- emergency health alerts
- real HealthKit integration
- real Google Health Connect integration
- real hardware drivers
- actuation or motor control
- consent storage
- policy enforcement changes
- persistence
- cloud sync
- AI or ML health interpretation

The registry should not make medical claims, regulatory claims, or hardware support claims.

## Relationship To Future Work

Capability Registry v1 should prepare the project for Consent Engine v1. Consent should later attach to registered capabilities, allowed purposes, and retention expectations.

The registry should also help future policy decisions become less abstract. Instead of asking only whether a request is low, medium, high, or critical risk, SomaGuard can ask what data is involved, why it is requested, whether consent exists, and whether retention is appropriate.

