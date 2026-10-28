/** @file Browser-only text/layout comparison using the deterministic Linux output corpus, without API credentials. */

/**
 * Run this function in the Admin origin's developer console. It imports the served
 * production modules, temporarily owns one isolated output element, and removes it
 * on success or failure. The synthetic corpus mirrors the 128-row Linux read trial;
 * this measures synchronous DOM write/layout, not compositor paint or a fleet SLA.
 */
export async function measureOutputRender() {
  const { renderJobOutput } = await import("/admin/app.js");
  const { createJobOutputReader, OUTPUT_WINDOW_BYTES } = await import("/admin/job-output-reader.js");
  const encoder = new TextEncoder();
  const rows = Array.from({ length: 128 }, (_, index) => {
    const i = index % 64;
    return { chunk_key: String(index + 1), agent_id: index < 64 ? "agent-ui-a" : "agent-ui-b",
      stream: i % 2 === 0 ? "stdout" : "stderr", sequence: String(Math.floor(i / 2)),
      data: `${String(i).padStart(4, "0")}|${"출력".repeat(2040)}\n` };
  });
  const counts = [0, 16, 32, 48, 64, 79, 95, 111, 127, 128];
  const pre = document.createElement("pre");
  pre.className = "snapshot output-viewer";
  pre.style.cssText = "position:fixed;bottom:0;right:0;width:640px;max-width:90vw;height:300px;overflow:auto;z-index:9999;white-space:pre-wrap;overflow-wrap:anywhere";
  document.body.append(pre);
  const results = [];
  const started = performance.now();
  let reader = null;
  try {
    for (let round = 0; round < 4; round++) {
      // Alternate order; discard the first round as a shared warm-up.
      for (const mode of round % 2 ? ["page", "full"] : ["full", "page"]) {
        let available = 0, position = 0, generation = 0;
        reader = createJobOutputReader({ api: { getJobOutputPage: async () => {
          const entries = rows.slice(position, Math.min(position + 4, available));
          position += entries.length;
          return { items: entries.map((row) => ({ ...row, offset_bytes: "0", total_bytes: String(encoder.encode(row.data).length), chunk_complete: true })),
            next_after: `op1.render-${++generation}`, has_more: position < available, caught_up: position >= available,
            history: "tracked", job_status: available === 128 ? "success" : "running" };
        } } });
        reader.reset("dom-output");
        pre.textContent = "";
        const result = { round, mode, formatOrReadMs: 0, domWriteLayoutMs: 0, writes: 0, finalTextBytes: 0 };
        for (const count of counts) {
          if (performance.now() - started > 15000) throw new Error("Render measurement exceeded its deadline.");
          available = count;
          const at = performance.now();
          let text;
          if (mode === "full") text = renderJobOutput(rows.slice(0, count), { jobId: "dom-output" });
          else {
            let snapshot;
            do { snapshot = await reader.read("dom-output", { signal: AbortSignal.timeout(1000) }); } while (snapshot.hasMore);
            text = snapshot.text;
            if (encoder.encode(text).length > OUTPUT_WINDOW_BYTES) throw new Error("DOM text exceeded its bound.");
          }
          result.formatOrReadMs += performance.now() - at;
          const writing = performance.now();
          if (pre.textContent !== text) { pre.textContent = text; result.writes++; }
          void pre.scrollHeight; // Force style/layout for the same visible element in both variants.
          result.domWriteLayoutMs += performance.now() - writing;
          result.finalTextBytes = encoder.encode(text).length;
        }
        reader.dispose(); reader = null;
        if (round > 0) results.push(result);
      }
    }
    return { counts, sourceBytes: rows.reduce((n, row) => n + encoder.encode(row.data).length, 0),
      warmupRounds: 1, measuredRounds: 3, results,
      scope: "Synthetic corpus matching Linux output; actual served modules and synchronous DOM write/layout; no paint/SLA claim" };
  } finally { reader?.dispose(); pre.remove(); }
}
