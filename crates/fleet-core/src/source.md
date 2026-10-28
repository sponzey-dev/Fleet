# Fleet Core Source Index

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `lib.rs` | Infrastructure | Exposes bootstrap, identity, configuration, and logging support shared by runtime composition. | No project-crate dependencies or application authorization ownership. |
| `controller_data.rs` | Infrastructure | Owns the private OS data-directory lease used by Controller and local identity bootstrap. | Creates missing private directories and a stable lock file; validates Unix ownership/modes/type/links; nonblocking process-lifetime flock and explicit release. |
| `id.rs` | Infrastructure | Produces time-sortable identifiers and optional semantic prefixes. | System clock and operating-system randomness. |
| `identity.rs` | Infrastructure | Generates and validates Ed25519 identity material and fingerprints. | Cryptographic primitives and operating-system randomness; no identity persistence. |
| `logging.rs` | Infrastructure | Installs the bootstrap-selected tracing subscriber and formats CLI severity prefixes. | Process logging initialization and stderr output. |
| `redaction.rs` | Infrastructure | Redacts recognized inline secret markers for caller-selected diagnostics. | String transformation only; does not authorize raw payload logging. |
| `settings.rs` | Infrastructure | Parses and validates immutable bootstrap settings and supported adapter selections. | Typed configuration boundary; no runtime configuration mutation. |
