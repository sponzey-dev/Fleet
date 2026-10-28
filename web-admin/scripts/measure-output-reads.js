/** @file Compares legacy formatting and bounded page consumption against one loopback Controller Job. */
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createApiClient } from "../api-client.js";
import { renderJobOutput } from "../app.js";
import { createJobOutputReader, OUTPUT_WINDOW_BYTES } from "../job-output-reader.js";

const bytes = (text) => Buffer.byteLength(text, "utf8");
const digest = (text) => createHash("sha256").update(text).digest("hex");

/**
 * Runs both reads at the same scheduled observations of an existing harmless Job.
 * Credentials stay in the caller's memory. Results contain counts/digests, never output or cursors.
 * Formatting timings measure JavaScript text construction, not browser paint or a Fleet-wide SLA.
 */
export async function measureOutputReadCosts({ origin, tokenProvider, jobId, scheduleMs, signal }) {
  const base = new URL(origin);
  if (base.origin !== origin || base.hostname !== "127.0.0.1" || !/^https?:$/.test(base.protocol)) {
    throw new Error("Measurement requires an explicit loopback origin.");
  }
  if (!Array.isArray(scheduleMs) || !scheduleMs.length || scheduleMs.length > 32
      || scheduleMs.some((t, i) => !Number.isInteger(t) || t < 0 || t > 180000 || (i && t <= scheduleMs[i - 1]))) {
    throw new Error("Use at most 32 increasing observation times within three minutes.");
  }
  const costs = { full: { requests: 0, bodyBytes: 0, textMs: 0 }, page: { requests: 0, bodyBytes: 0, consumeMs: 0 } };
  const lifetime = AbortSignal.any([AbortSignal.timeout(180000), ...(signal ? [signal] : [])]);
  const rows = new Map();
  let corpusBytes = 0;
  let pageNetworkMs = 0;
  const client = createApiClient({ tokenProvider, fetchImpl: async (path, options) => {
    const started = performance.now();
    const response = await fetch(new URL(path, origin), {
      ...options, signal: AbortSignal.any([lifetime, AbortSignal.timeout(10000), ...(options.signal ? [options.signal] : [])]),
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`Measurement HTTP ${response.status}.`);
    const kind = path.includes("/output-page?") ? "page" : path.endsWith("/output") ? "full" : null;
    if (kind) { costs[kind].requests++; costs[kind].bodyBytes += bytes(body); }
    const value = JSON.parse(body);
    if (kind === "page") {
      pageNetworkMs += performance.now() - started;
      for (const fragment of value.items) {
        if (typeof fragment.chunk_key !== "string") throw new Error("Measurement requires a canonical chunk key.");
        let row = rows.get(fragment.chunk_key);
        if (!row) {
          row = { agent_id: fragment.agent_id, stream: fragment.stream, sequence: fragment.sequence, data: "" };
          rows.set(fragment.chunk_key, row);
        }
        if (String(bytes(row.data)) !== fragment.offset_bytes) throw new Error("Measurement fragment offset conflict.");
        row.data += fragment.data;
        corpusBytes += bytes(fragment.data);
        if (corpusBytes > 8 * 1024 * 1024) throw new Error("Measurement corpus exceeds its 8 MiB fixture bound.");
      }
    }
    return { ok: true, status: response.status, json: async () => value };
  } });
  const reader = createJobOutputReader({ api: client });
  reader.reset(jobId);
  const started = performance.now();
  const samples = [];
  let finalFull = [];
  try {
    for (const scheduledMs of scheduleMs) {
      await delay(Math.max(0, scheduledMs - (performance.now() - started)), undefined, { signal: lifetime });
      const observedMs = performance.now() - started;
      const [full, page] = await Promise.all([
        client.getJobOutput(jobId).then((chunks) => {
          const at = performance.now();
          const text = renderJobOutput(chunks, { jobId });
          costs.full.textMs += performance.now() - at;
          return { chunks, textBytes: bytes(text) };
        }),
        (async () => {
          const at = performance.now(), network = pageNetworkMs;
          let snapshot;
          do { snapshot = await reader.read(jobId, { signal: lifetime }); } while (snapshot.hasMore);
          costs.page.consumeMs += Math.max(0, performance.now() - at - (pageNetworkMs - network));
          if (bytes(snapshot.text) > OUTPUT_WINDOW_BYTES) throw new Error("Display window exceeded its byte bound.");
          return snapshot;
        })(),
      ]);
      finalFull = full.chunks;
      samples.push({ scheduledMs, observedMs, fullRows: full.chunks.length, fullTextBytes: full.textBytes,
        pageWindowBytes: bytes(page.text), pageWindowFragments: page.fragments.length, trimmed: page.trimmed,
        history: page.history, pageStatus: page.jobStatus, caughtUp: page.caughtUp });
    }
    const canonical = (values) => values.map((row) => ({
      agent: row.agent_id, stream: row.stream, sequence: String(row.sequence), bytes: bytes(row.data), sha256: digest(row.data),
    })).sort((a, b) => a.agent.localeCompare(b.agent) || a.stream.localeCompare(b.stream)
      || (BigInt(a.sequence) < BigInt(b.sequence) ? -1 : BigInt(a.sequence) > BigInt(b.sequence) ? 1 : 0));
    const fullRows = canonical(finalFull), pageRows = canonical([...rows.values()]);
    const equal = JSON.stringify(fullRows) === JSON.stringify(pageRows);
    if (!equal) throw new Error("Final full/page corpus differs; rerun with a final observation after terminal drain.");
    return { origin, jobId, scheduleMs, samples, costs, exactRows: fullRows.length, sourceBytes: corpusBytes,
      corpusSha256: digest(JSON.stringify(fullRows)), exactReassembly: equal,
      repeatedBodyBytesReduced: costs.page.bodyBytes < costs.full.bodyBytes,
      timings: "JavaScript text construction/page consumption excluding measured HTTP; no DOM paint or fleet SLA claim" };
  } finally { reader.dispose(); }
}
