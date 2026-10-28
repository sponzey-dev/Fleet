# Fleet Runner Source Index

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `lib.rs` | Infrastructure | Runs host command/package/service/file/template primitives, verifies signed envelopes and durable nonce replay, and collects drift evidence. | Process, filesystem, network probe, and operating-system effects; no Controller store access. |
| `process_stream.rs` | Infrastructure | Owns Darwin/Linux command process groups and bounded stdout/stderr polling until exit, cancellation, timeout, or callback failure; sequences chunks contiguously from zero independently per stream. | Spawns/kills/reaps only the new process group while its leader is unreaped; no journal access or restart PID discovery. |
