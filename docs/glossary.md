# Glossary

## Human Device Trust Layer

A defensive boundary between a person, software systems, and simulated body-adjacent device capabilities. It decides how requests should be reviewed, allowed, denied, paused, logged, or stopped.

## Body-Adjacent Device

A device concept that is worn, carried close to the body, used near perception, or related to movement or personal signals. In this project, all body-adjacent devices are simulated only.

## Device Capability

A specific action or function a simulated device can represent. Examples include reading simulated status, showing a simulated AR overlay, or entering a safer mode.

## Capability Registry

A shared list of registered simulated capabilities and their metadata, such as sensitivity, purpose, retention hint, and source device type. It gives policy, consent, audit, and scenario layers a common vocabulary.

## Data Sensitivity

A label for how privacy-sensitive a simulated data access may be. Body-adjacent data should not be treated as automatically low risk.

## Purpose Binding

The principle that future consent should be tied to a specific reason for access, not only a broad yes/no approval.

## Permission

A limited approval for a requester to use a specific simulated capability. Permission should have a clear purpose and scope.

## Consent

The human's informed agreement to allow a simulated action or category of actions. Consent should be understandable, specific, and revocable.

## Safety Mode

A named operating state that changes how cautious the system should be. A safety mode may require human review, block some actions, or limit the system to observation.

## Emergency Lock

A high-priority stop condition that blocks sensitive simulated actions. It represents the principle that the human or safety process can halt activity when needed.

## Audit Log

A record of important simulated events and decisions. An audit log should be readable by humans and structured enough for later review.

## Quarantine

A defensive state for an app, device, or capability that should not be trusted. Quarantine limits or blocks activity until the issue is reviewed.

## Policy Engine

The conceptual decision-making part of the trust layer. It evaluates permission, consent, safety mode, quarantine state, risk, and emergency lock status before a simulated action is allowed.
