/** @file Bounded, owner-scoped consumption of stored output pages; no DOM or persistence. */
export const OUTPUT_WINDOW_BYTES = 1024 * 1024;
export const OUTPUT_WINDOW_FRAGMENTS = 2048;
const PAGE_FRAGMENTS = 128;
const PAGE_BYTES = 65536;
const MAX_READ_PAGES = 4;
const MAX_INTEGER = 9223372036854775807n;
const encoder = new TextEncoder();
const STATUSES = new Set(["draft", "pending_approval", "queued", "running", "partial_success", "success", "failed", "canceled", "expired"]);
const HISTORIES = new Set(["tracked", "unknown", "pruned"]);
const PAGE_FIELDS = new Set(["items", "next_after", "has_more", "caught_up", "history", "job_status"]);
/** @type {Set<keyof StoredFragment>} */
const FRAGMENT_FIELDS = new Set(["chunk_key", "agent_id", "stream", "sequence", "offset_bytes", "total_bytes", "data", "chunk_complete"]);

/** @typedef {{chunk_key:string, agent_id:string, stream:string, sequence:string, offset_bytes:string, total_bytes:string, data:string, chunk_complete:boolean}} StoredFragment */
/** @typedef {{fragment:Readonly<StoredFragment>, bytes:number, cost:number}} Entry */
/** @typedef {{fragments:readonly Readonly<StoredFragment>[], text:string, history:string|null, hasMore:boolean, caughtUp:boolean, jobStatus:string|null, trimmed:boolean, pages:number, added:number, empty:boolean, startedOpen:boolean}} OutputReadSnapshot */
/** @typedef {{agentId?:string, stream?:string}} OutputScope */
/** @typedef {{getJobOutputPage:(id:string, options:{after?:string, agentId?:string, stream?:string, limit:number, maxBytes:number, signal:AbortSignal})=>Promise<unknown>}} OutputPageApi */
/** @typedef {{id:string, scope:Readonly<OutputScope>, records:Entry[], last:Entry|null, after:string|undefined, open:boolean, history:string|null, hasMore:boolean, caughtUp:boolean, jobStatus:string|null, trimmed:boolean, reading:object|null, mode:string|null}} ReadContext */

export class OutputReadError extends Error {
  constructor(kind = "invalid_response") {
    super("Stored output could not be verified. Reopen the output to read again.");
    this.name = "OutputReadError";
    this.kind = kind;
  }
}

/** @param {unknown} value @param {Set<string>} fields @returns {Record<string,unknown>} */
function object(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== fields.size || Object.keys(value).some((key) => !fields.has(key))) throw new OutputReadError();
  return /** @type {Record<string,unknown>} */ (value);
}

/** Reject lone surrogates rather than silently replacing original bytes. @param {string} value */
function utf8Bytes(value) {
  for (const character of value) {
    const cp = character.codePointAt(0) ?? 0;
    if (cp >= 0xd800 && cp <= 0xdfff) throw new OutputReadError();
  }
  return encoder.encode(value).length;
}

/** @param {unknown} value @param {boolean} positive @returns {string} */
function decimal(value, positive = false) {
  if (typeof value !== "string" || value.length > 19 || !/^(0|[1-9][0-9]*)$/.test(value)
      || BigInt(value) > MAX_INTEGER || (positive && value === "0")) throw new OutputReadError();
  return value;
}

/** @param {unknown} value @returns {Entry} */
function parseFragment(value) {
  const f = object(value, FRAGMENT_FIELDS);
  if (typeof f.agent_id !== "string" || !f.agent_id.trim() || f.agent_id.length > PAGE_BYTES
      || typeof f.stream !== "string" || !["stdout", "stderr"].includes(f.stream) || typeof f.data !== "string" || f.data.length > PAGE_BYTES
      || typeof f.chunk_complete !== "boolean") throw new OutputReadError();
  const chunk_key = decimal(f.chunk_key, true), sequence = decimal(f.sequence);
  const offset_bytes = decimal(f.offset_bytes), total_bytes = decimal(f.total_bytes);
  const bytes = utf8Bytes(f.data), end = BigInt(offset_bytes) + BigInt(bytes), total = BigInt(total_bytes);
  if (end > total || (bytes === 0 && total !== 0n) || f.chunk_complete !== (end === total)) throw new OutputReadError();
  const fragment = Object.freeze({ chunk_key, agent_id: f.agent_id, stream: /** @type {string} */(f.stream), sequence, offset_bytes, total_bytes, data: f.data, chunk_complete: f.chunk_complete });
  // This upper bound includes a group header and a missing-portion notice for
  // every fragment. The actual grouped rendering is no larger than this budget.
  const cost = bytes + utf8Bytes(f.agent_id) + String(f.stream).length + sequence.length + offset_bytes.length + 128;
  return { fragment, bytes, cost };
}

/** @param {unknown} value */
function parsePage(value) {
  const page = object(value, PAGE_FIELDS);
  if (!Array.isArray(page.items) || page.items.length > PAGE_FRAGMENTS
      || typeof page.next_after !== "string" || page.next_after.length > 2735 || !/^op1\.[A-Za-z0-9_-]+$/.test(page.next_after)
      || typeof page.has_more !== "boolean" || typeof page.caught_up !== "boolean"
      || (page.has_more && page.caught_up) || (page.has_more && page.items.length === 0)
      || typeof page.history !== "string" || !HISTORIES.has(page.history)
      || typeof page.job_status !== "string" || !STATUSES.has(page.job_status)) throw new OutputReadError();
  const entries = page.items.map(parseFragment);
  if (entries.reduce((sum, e) => sum + e.bytes + utf8Bytes(e.fragment.agent_id) + e.fragment.stream.length, 0) > PAGE_BYTES) throw new OutputReadError();
  return { entries, after: page.next_after, hasMore: page.has_more, caughtUp: page.caught_up, history: page.history, jobStatus: page.job_status };
}

/** @param {Readonly<StoredFragment>} f */
function key(f) { return `${f.chunk_key}:${f.offset_bytes}`; }
/** @param {Readonly<StoredFragment>} f */
function streamKey(f) { return JSON.stringify([f.agent_id, f.stream, f.sequence]); }
/** @param {Readonly<StoredFragment>} a @param {Readonly<StoredFragment>} b */
function same(a, b) { return [...FRAGMENT_FIELDS].every((field) => a[field] === b[field]); }

/** @param {Entry[]} entries @param {boolean} trimmed @param {string|null} history */
function formatWindow(entries, trimmed, history) {
  const ordered = [...entries].sort((a, b) => {
    const x = a.fragment, y = b.fragment;
    if (x.agent_id !== y.agent_id) return x.agent_id < y.agent_id ? -1 : 1;
    if (x.stream !== y.stream) return x.stream === "stdout" ? -1 : 1;
    for (const [a, b] of [[x.sequence, y.sequence], [x.offset_bytes, y.offset_bytes], [x.chunk_key, y.chunk_key]]) {
      const left = BigInt(a), right = BigInt(b);
      if (left !== right) return left < right ? -1 : 1;
    }
    return 0;
  });
  const parts = [];
  if (trimmed) parts.push("Some previously displayed output is outside this view. Browse stored history.\n");
  if (history === "unknown") parts.push("Stored history before tracking is unknown.\n");
  if (history === "pruned") parts.push("Some stored output was removed by retention.\n");
  /** @type {Entry|null} */
  let previous = null;
  for (const entry of ordered) {
    const f = entry.fragment, p = previous?.fragment;
    const sameStream = p?.agent_id === f.agent_id && p?.stream === f.stream;
    if (!sameStream) parts.push(`${previous ? "\n\n" : ""}[${f.agent_id} · ${f.stream}]\n`);
    const contiguous = sameStream && p && previous && ((p.sequence === f.sequence && BigInt(p.offset_bytes) + BigInt(previous.bytes) === BigInt(f.offset_bytes))
      || (p.chunk_complete && BigInt(f.sequence) === BigInt(p.sequence) + 1n && f.offset_bytes === "0"));
    if ((!sameStream && (f.sequence !== "0" || f.offset_bytes !== "0")) || (sameStream && !contiguous)) {
      parts.push("\n[Portions of stored output are not present in this display window.]\n");
    }
    parts.push(f.total_bytes === "0" ? "[Empty stored chunk]\n" : f.data);
    previous = entry;
  }
  return parts.join("");
}

/** @param {string} id @param {Readonly<OutputScope>} scope @returns {ReadContext} */
function fresh(id = "", scope = {}) {
  return { id, scope, records: [], last: null, after: undefined, open: true, history: null,
    hasMore: false, caughtUp: false, jobStatus: null, trimmed: false, reading: null, mode: null };
}

/** Plans an entire page before changing its owner. @param {ReadContext} ctx @param {ReturnType<typeof parsePage>} page @param {boolean} history */
function applyPage(ctx, page, history) {
  if (ctx.history !== null && ctx.history !== page.history) throw new OutputReadError("stale");
  let records = history ? [] : [...ctx.records];
  const index = new Map(ctx.records.map((e) => [key(e.fragment), e]));
  const streams = new Map(ctx.records.map((e) => [streamKey(e.fragment), e.fragment.chunk_key]));
  let last = ctx.last, added = 0;
  for (const entry of page.entries) {
    const f = entry.fragment;
    if ((ctx.scope.agentId !== undefined && f.agent_id !== ctx.scope.agentId) || (ctx.scope.stream !== undefined && f.stream !== ctx.scope.stream)) throw new OutputReadError();
    const known = index.get(key(f));
    if (known) {
      if (!same(known.fragment, f)) throw new OutputReadError("conflict");
      if (history && !records.some((e) => key(e.fragment) === key(f))) records.push(known);
      continue;
    }
    const chunkOwner = streams.get(streamKey(f));
    if (chunkOwner && chunkOwner !== f.chunk_key) throw new OutputReadError("conflict");
    const row = BigInt(f.chunk_key), priorRow = last ? BigInt(last.fragment.chunk_key) : 0n;
    if (row < priorRow) throw new OutputReadError("conflict"); // An unverifiable old replay outside the retained window.
    if (last && row === priorRow) {
      const p = last.fragment;
      if (p.agent_id !== f.agent_id || p.stream !== f.stream || p.sequence !== f.sequence || p.total_bytes !== f.total_bytes) throw new OutputReadError("conflict");
      const end = BigInt(p.offset_bytes) + BigInt(last.bytes);
      if (BigInt(f.offset_bytes) < end) throw new OutputReadError("conflict");
      if (BigInt(f.offset_bytes) !== end) throw new OutputReadError("gap");
    } else if (f.offset_bytes !== "0" || (last && !last.fragment.chunk_complete)) throw new OutputReadError("gap");
    records.push(entry); index.set(key(f), entry); streams.set(streamKey(f), f.chunk_key); last = entry; added += 1;
  }
  if ((last && !last.fragment.chunk_complete && !page.hasMore) || ((!page.caughtUp || added > 0) && page.after === ctx.after)) throw new OutputReadError();
  let cost = records.reduce((sum, e) => sum + e.cost, 0), trimmed = history ? false : ctx.trimmed;
  while (records.length > OUTPUT_WINDOW_FRAGMENTS || cost > OUTPUT_WINDOW_BYTES - 512) {
    const removed = records.shift();
    if (!removed) throw new OutputReadError();
    cost -= removed.cost; trimmed = true;
  }
  const text = formatWindow(records, trimmed, page.history);
  if (utf8Bytes(text) > OUTPUT_WINDOW_BYTES) throw new OutputReadError();
  return { records, last, added, trimmed, after: page.after, open: !page.hasMore, history: page.history,
    hasMore: page.hasMore, caughtUp: page.caughtUp, jobStatus: page.jobStatus };
}

/**
 * Owns one Job/filter cursor and display window, never a complete output archive.
 * The caller owns deadlines/AbortSignal. Retired reads cannot commit; HTTP errors
 * propagate without a full-array fallback. History reads replace a single page.
 * @param {{api:OutputPageApi}} options
 */
export function createJobOutputReader({ api }) {
  if (typeof api?.getJobOutputPage !== "function") throw new TypeError("An output page API is required.");
  let ctx = fresh(), disposed = false;
  /** @param {ReadContext} context @returns {Readonly<OutputReadSnapshot>} */
  function snapshot(context) {
    return Object.freeze({ fragments: Object.freeze(context.records.map((e) => e.fragment)), text: formatWindow(context.records, context.trimmed, context.history),
      history: context.history, hasMore: context.hasMore, caughtUp: context.caughtUp, jobStatus: context.jobStatus, trimmed: context.trimmed,
      pages: 0, added: 0, empty: true, startedOpen: context.open });
  }
  /** @param {string} jobId @param {{signal:AbortSignal}} options @param {boolean} history */
  async function read(jobId, { signal }, history) {
    signal.throwIfAborted();
    const owner = ctx;
    if (disposed || owner.id !== jobId || owner.reading || (owner.mode && owner.mode !== (history ? "history" : "live"))) throw new OutputReadError();
    const readToken = {};
    owner.mode = history ? "history" : "live"; owner.reading = readToken;
    const startedOpen = owner.open;
    let pages = 0, added = 0, empty = true;
    let onAbort = () => {};
    /** @type {Promise<never>} */
    const canceled = new Promise((_, reject) => {
      onAbort = () => {
        if (owner.reading === readToken) owner.reading = null;
        reject(signal.reason);
      };
      signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      for (let i = 0; i < (history ? 1 : MAX_READ_PAGES); i += 1) {
        signal.throwIfAborted();
        const value = await Promise.race([api.getJobOutputPage(jobId, { ...owner.scope, after: owner.after, limit: PAGE_FRAGMENTS, maxBytes: PAGE_BYTES, signal }), canceled]);
        signal.throwIfAborted();
        if (disposed || owner !== ctx) throw new DOMException("Output read retired.", "AbortError");
        const page = parsePage(value), next = applyPage(owner, page, history);
        pages += 1; added += next.added; empty = empty && page.entries.length === 0;
        Object.assign(owner, next);
        if (page.caughtUp) break;
      }
      return Object.freeze({ ...snapshot(owner), pages, added, empty, startedOpen });
    } finally {
      signal.removeEventListener("abort", onAbort);
      if (owner.reading === readToken) owner.reading = null;
      if (owner !== ctx) { owner.records = []; owner.last = null; }
    }
  }
  return {
    /** @param {string} jobId @param {OutputScope} scope */
    reset(jobId, scope = {}) {
      if (disposed || typeof jobId !== "string" || !jobId.trim() || Object.keys(scope).some((k) => !["agentId", "stream"].includes(k))
          || (scope.agentId !== undefined && (typeof scope.agentId !== "string" || !scope.agentId.trim()))
          || (scope.stream !== undefined && !["stdout", "stderr"].includes(scope.stream))) throw new OutputReadError();
      ctx.records = []; ctx.last = null;
      ctx = fresh(jobId, Object.freeze({ ...scope }));
    },
    /** Reads at most four pages. The caller must yield before scheduling another batch. @param {string} jobId @param {{signal:AbortSignal}} options */
    read(jobId, options) { return read(jobId, options, false); },
    /** @param {string} jobId @param {{signal:AbortSignal}} options */
    readHistoryPage(jobId, options) { return read(jobId, options, true); },
    getSnapshot: () => snapshot(ctx),
    dispose() { disposed = true; ctx.records = []; ctx.last = null; ctx = fresh(); },
  };
}
