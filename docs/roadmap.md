# Roadmap

This roadmap keeps SomaGuard documentation-first and simulation-first. No code, package manifest, dependencies, API, or UI should be added during the initial documentation phase.

## Phase 0: Concept Lock

Goal:

Define the project identity, safety boundaries, core principle, and basic vocabulary.

Deliverables:

- README
- Vision document
- Ethics document
- Glossary
- Roadmap

Success criteria:

- The project is clearly described as defensive and simulation-only.
- The core principle, "Keep the human in control," is visible.
- The misuse boundaries are explicit.
- No implementation files exist.

## Phase 1: Static Simulation

Goal:

Describe static simulated scenarios without building runtime behavior.

Deliverables:

- Written scenario examples
- Simulated device capability descriptions
- Capability Registry v1 scope for PulseBand Sim
- Permission and consent examples
- Safety mode examples

Success criteria:

- Scenarios are non-medical and non-operational.
- No real hardware or body-affecting behavior is described.
- Each scenario explains the human control point.

## Phase 2: Interactive Console

Goal:

Plan a possible future console-style simulation for reviewing trust decisions, while keeping the current phase documentation-only.

Deliverables:

- Console concept document
- Example decision flow diagrams
- Human review interaction notes
- Non-goals and safety boundaries for any future prototype

Success criteria:

- The console remains a future concept, not an implementation.
- The design emphasizes review, denial, and human override.
- No API, UI, or dependency decisions are introduced in this phase.

## Phase 3: Update Guard

Goal:

Define how a trust layer should think about simulated updates, rollback, quarantine, and safety review.

Deliverables:

- Update guard concept document
- Simulated update risk categories
- Rollback and quarantine notes
- Audit expectations for update events

Success criteria:

- Update behavior is framed defensively.
- No real update system or package execution is introduced.
- Quarantine and rollback remain conceptual and simulation-only.

## Phase 4: Scenario Lab

Goal:

Expand the research set with structured scenario studies.

Deliverables:

- Scenario lab outline
- Scenario templates
- Misuse review checklist
- Human control checklist

Success criteria:

- Each scenario has a clear safety boundary.
- Each scenario identifies consent, permission, safety mode, audit, and emergency lock considerations.
- Scenarios avoid operational details that could enable misuse.

## Phase 5: Research Package

Goal:

Prepare the project as a coherent research package for review, discussion, or future safe prototyping.

Deliverables:

- Consolidated architecture overview
- Ethics and misuse review
- Glossary revision
- Roadmap revision
- Future implementation guardrails

Success criteria:

- The package can be read without implementation context.
- The defensive purpose is clear.
- Future work is gated by safety review.
- The project remains calm, serious, and technically grounded.
