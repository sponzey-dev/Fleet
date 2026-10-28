//! Explicit, fake-only cost measurements isolated from production authentication.
//! These tests report durations and public resource sizes, never derived bytes.

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

const SAMPLES: usize = 12;
const OUTPUT_LENGTH: usize = 32;

fn derive(memory_kib: u32, passes: u32) {
    let params = Params::new(memory_kib, passes, 1, Some(OUTPUT_LENGTH)).unwrap();
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0; OUTPUT_LENGTH];
    kdf.hash_password_into(
        std::hint::black_box(b"isolated measurement fixture"),
        &[7; 16],
        &mut output,
    )
    .unwrap();
    std::hint::black_box(output);
}

#[test]
#[ignore = "explicit fake-only Argon2id measurement; no production credential or listener"]
fn argon2_cost_candidates() {
    let mut cases = Vec::new();
    for memory_kib in [19_456, 32_768, 65_536] {
        derive(memory_kib, 2);
        let mut samples = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let start = Instant::now();
            derive(memory_kib, 2);
            samples.push(start.elapsed().as_micros());
        }
        samples.sort_unstable();
        cases.push(serde_json::json!({
            "memory_kib": memory_kib,
            "passes": 2,
            "lanes": 1,
            "samples": SAMPLES,
            "warmup": 1,
            "p50_us": samples[SAMPLES / 2],
            "p95_us": samples[SAMPLES * 95 / 100],
            "max_us": samples[SAMPLES - 1]
        }));
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "argon2id_cost_candidates",
            "debug_assertions": cfg!(debug_assertions),
            "library": "RustCrypto argon2 0.6",
            "cases": cases,
            "limits": "fixed candidate set; one live derivation; fake input only",
            "scope": "local crypto cost, excludes Controller/TLS/Agent workload"
        })
    );
}

#[test]
#[ignore = "explicit joined-thread scaling measurement; no queue, server or real credential"]
fn argon2_parallelism_candidates() {
    let mut cases = Vec::new();
    for workers in [1, 2] {
        let start = Instant::now();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        for _ in 0..4 {
                            derive(19_456, 2);
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
        });
        cases.push(serde_json::json!({
            "workers": workers,
            "hashes": workers * 4,
            "elapsed_us": start.elapsed().as_micros(),
            "scratch_upper_kib": workers * 19_456
        }));
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "argon2id_parallelism_candidates",
            "debug_assertions": cfg!(debug_assertions),
            "memory_kib": 19_456,
            "passes": 2,
            "lanes": 1,
            "cases": cases,
            "limits": "at most two joined threads; no outstanding queue",
            "scope": "local scaling; worker admission/shutdown safety tested in production adapter task"
        })
    );
}
