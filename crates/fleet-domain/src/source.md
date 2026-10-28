# Fleet Domain Source Index

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `admin_account.rs` | Domain | Defines administrator account state, checked revisions and last-owner/credential-invalidation transitions. | Pure aggregate effects only; Application supplies actor authority and transactionally consistent owner counts and owns persistence/audit. |
| `admin_credential.rs` | Domain | Defines purpose-bound human credentials, fixed expiry, bounded optional PAT labels, revocation, single-use grants and restore authentication mode. | Pure lifecycle; Application supplies current account, human epoch and time inside canonical transactions; adapters own token proof. |
| `admin_identity.rs` | Domain | Defines administrator permissions, validated user identifiers/names and bounded redacted password/verifier values. | Pure validation and role policy; adapters own normalization, hashing and lookup, while Application enforces subject ownership and account state. |
| `agent.rs` | Domain | Defines agent identity, labels, lifecycle, and runtime profile rules. | Pure validation and state transitions; no I/O. |
| `assignment_recovery.rs` | Domain | Assesses overdue dispatched/accepted/started work from Controller dispatch time, execution timeout, and grace. | Pure deadline calculation; uncertain execution never becomes success or reexecution authority. |
| `artifact.rs` | Domain | Defines artifact identity, retention classification, and metadata validation. | Pure data validation; no storage access. |
| `audit.rs` | Domain | Defines auditable actors, targets, values, and events. | Pure event construction; no log or database writes. |
| `capability.rs` | Domain | Defines agent capability snapshots and compatibility decisions. | Pure policy evaluation; no system probes. |
| `catalog.rs` | Domain | Defines public catalog identity with validated HTTPS authority, immutable revision, Runbook Job and Policy provenance, sync-operation and activation guards, and document metadata. | Pure validation and transitions; no Git, database, or network access. |
| `certificate.rs` | Domain | Defines certificate lifecycle and revocation state. | Pure state transitions; no TLS or filesystem access. |
| `delivery.rs` | Domain | Defines report classes and acknowledgement matching, reserved capacity, execution admission/start-intent/result states with interruption reasons, and contiguous per-stream output progress. | Pure rules; DriftEvidence classification carries no policy provenance or execution-success meaning; no authentication, deletion, serialization, execution, or persistence. |
| `job.rs` | Domain | Defines jobs, assignments, task envelopes, and execution state transitions. | Pure execution policy; no dispatch or process I/O. |
| `policy.rs` | Domain | Defines policies, drift reports, verified remediation-origin candidate validation, and remediation rules. | Pure parsing and policy decisions; no persistence or transport access. |
| `runbook.rs` | Domain | Defines runbook task structures and validation. | Pure parsing and validation; no task execution. |
| `secret.rs` | Domain | Defines secret references and safe template boundaries. | Pure reference validation; never resolves secret material. |
| `selector.rs` | Domain | Defines agent selector parsing and matching. | Pure matching; no repository access. |
| `signing.rs` | Domain | Defines controller signing trust and rotation state. | Pure cryptographic policy state; no key-store I/O. |
| `lib.rs` | Domain | Exposes domain modules and shared domain identity. | No external side effects. |
