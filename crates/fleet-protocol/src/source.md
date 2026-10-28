# Fleet Protocol Source Index

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `lib.rs` | Protocol | Defines active v2 Controller-Agent session messages, including bounded report/receipt payloads, authenticated-session identity, and version-first JSON encoding/decoding. | Serializes and parses wire data; owns no network transport or persistence. |
| `delivery_v2.rs` | Protocol | Defines v2 report envelope checks and strict TaskAck/TaskStarted/TaskRejected lifecycle, DriftEvidence, and final-result body contracts, including required per-stream output counts and truncation summary. | Shape/content validation only; no socket authentication, receipt signature verification, or persistence. |
| `receipt.rs` | Protocol | Defines the v2 signed report-receipt statement, strict shape checks, and domain-separated canonical signing bytes. | No cryptography, trust decision, active wire dispatch, database write, or journal deletion. |
