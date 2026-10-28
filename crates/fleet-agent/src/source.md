# Fleet Agent Source Index

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `lib.rs` | Application | Owns the process-local agent connection, active-task, and bounded report-outbox state. | Pure in-memory state only; the CLI adapter owns socket I/O and process execution. |
| `journal_worker.rs` | Infrastructure | Owns one blocking journal worker, bounded requests and completion leases, and typed queue/admission/start/receipt operations through Application ports. | Thread/channel lifecycle and joined shutdown; no concrete database or socket dependency, no raw report diagnostics. |
| `receipt_verifier.rs` | Infrastructure | Verifies a v2 Controller signed stored-report receipt against pinned/rotated trust and the exact local pending report. | Ed25519 validation only; no live socket path or journal deletion. |
