/** @file Owner-scoped, body-free Catalog page reads; canonical mutations belong to explicit API commands. */
const LEVELS = ["sources", "revisions", "documents"];
const PAGE_LIMIT = 50;
const utf8 = new TextEncoder();
const initialPage = () => ({ phase: "idle", items: Object.freeze([]), after: undefined, nextAfter: null,
  pageNumber: 0, error: null, lastRequest: null });

class CatalogReadError extends Error {
  constructor() { super("Catalog metadata could not be verified."); this.kind = "invalid_response"; }
}

function text(value) {
  if (typeof value !== "string" || !value || value.includes("\0")) throw new CatalogReadError();
  return value;
}

function nullableText(value) { return value === null ? null : text(value); }
function key(level, item) { return level === "sources" ? item.id : level === "revisions" ? item.commit : item.path; }
function compare(a, b) {
  const left = utf8.encode(a), right = utf8.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i++) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}

/** Copies only the public metadata fields; list responses must never contain a document body. */
function item(level, value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || "body" in value) throw new CatalogReadError();
  if (level === "sources") return Object.freeze({ id: text(value.id), url: text(value.url),
    reference: text(value.reference), active_commit: nullableText(value.active_commit) });
  if (level === "revisions") {
    if (!["fetching", "validating", "ready", "failed"].includes(value.state)
        || !(value.document_count === null || (Number.isSafeInteger(value.document_count) && value.document_count >= 0))) throw new CatalogReadError();
    return Object.freeze({ commit: text(value.commit), state: value.state, document_count: value.document_count,
      failure: nullableText(value.failure) });
  }
  if (!["runbook", "policy"].includes(value.kind)) throw new CatalogReadError();
  return Object.freeze({ kind: value.kind, path: text(value.path), checksum: text(value.checksum) });
}

function parsePage(level, value, request) {
  if (!value || typeof value !== "object" || !Array.isArray(value.items) || value.items.length > PAGE_LIMIT) throw new CatalogReadError();
  const nextAfter = nullableText(value.next_after);
  if (nextAfter !== null && (!value.items.length || nextAfter === request.after)) throw new CatalogReadError();
  const items = Object.freeze(value.items.map((entry) => item(level, entry)));
  let prior = request.boundary;
  for (const entry of items) {
    const current = key(level, entry);
    if (prior !== null && compare(prior, current) >= 0) throw new CatalogReadError();
    prior = current;
  }
  return { items, nextAfter };
}

function failure(error) {
  const status = Number.isInteger(error?.status) ? error.status : null;
  const kind = error instanceof CatalogReadError ? "invalid_response" : error?.name === "TimeoutError" ? "timeout"
    : status === 401 ? "authentication" : status === 403 ? "forbidden" : status === 404 ? "not_found"
    : status !== null ? "http" : "network";
  return Object.freeze({ kind, status, retryable: ["timeout", "network"].includes(kind) || (status !== null && status >= 500) });
}

/**
 * Owns one page per list and explicit parent/document selections. Reads never
 * mutate the catalog, execute work or fetch document bodies. Cursors stay private;
 * route/auth changes retire all requests, including effects that ignore abort.
 * The caller owns the component lifetime and must dispose it when unmounted.
 * @param {{api:{listCatalogSources:(options:{limit:number,after?:string,signal:AbortSignal})=>unknown,
 * listCatalogRevisions:(id:string,options:{limit:number,after?:string,signal:AbortSignal})=>unknown,
 * listCatalogDocuments:(id:string,commit:string,options:{limit:number,after?:string,signal:AbortSignal})=>unknown},
 * onChange?:(snapshot:object)=>void,clock?:{setTimeout:(fn:()=>void,ms:number)=>number,clearTimeout:(id:number)=>void}}} options
 */
export function createCatalogExplorer({ api, onChange = () => {}, clock = globalThis }) {
  let pages = Object.fromEntries(LEVELS.map((level) => [level, initialPage()]));
  const pending = Object.fromEntries(LEVELS.map((level) => [level, null]));
  let authGeneration = 0;
  let route = "", authenticated = false, active = false, disposed = false, viewFailed = false;
  let context = {}, sourceOwner = {}, revisionOwner = {};
  let selectedSource = null, selectedRevision = null, selectedDocument = null, selectionStale = false;

  function snapshot() {
    return Object.freeze({ active, selectedSource, selectedRevision, selectedDocument, selectionStale,
      selectedRevisionActive: Boolean(selectedRevision && selectedSource?.active_commit === selectedRevision.commit),
      ...Object.fromEntries(LEVELS.map((level) => [level, Object.freeze({ phase: pages[level].phase,
        items: pages[level].items, hasNext: pages[level].nextAfter !== null, pageNumber: pages[level].pageNumber, error: pages[level].error })])) });
  }
  function retire(level) {
    const request = pending[level]; pending[level] = null;
    if (request) { clock.clearTimeout(request.timer); request.controller.abort(new DOMException("Catalog read retired.", "AbortError")); }
  }
  function publish() {
    try { onChange(snapshot()); return true; }
    catch {
      viewFailed = true;
      for (const level of LEVELS) {
        retire(level);
        if (pages[level].phase === "loading") pages[level] = { ...pages[level], phase: "error", error: Object.freeze({ kind: "view", status: null, retryable: false }) };
      }
      return false;
    }
  }
  function clear() {
    for (const level of LEVELS) retire(level);
    pages = Object.fromEntries(LEVELS.map((level) => [level, initialPage()]));
    context = {}; sourceOwner = {}; revisionOwner = {};
    selectedSource = null; selectedRevision = null; selectedDocument = null; selectionStale = false;
  }

  async function load(level, { next = false, retry = false } = {}) {
    if (!LEVELS.includes(level)) throw new TypeError("Unknown catalog list.");
    if (!active || disposed || viewFailed || (level !== "sources" && !selectedSource) || (level === "documents" && !selectedRevision)) return;
    const prior = pages[level];
    if (next && (pending[level] || prior.phase !== "ready" || prior.nextAfter === null)) return;
    const position = retry && prior.lastRequest ? prior.lastRequest : {
      after: next ? prior.nextAfter : undefined,
      boundary: next && prior.items.length ? key(level, prior.items.at(-1)) : null,
      pageNumber: next ? prior.pageNumber + 1 : 1,
    };
    retire(level);
    const controller = new AbortController();
    const request = { controller, timer: clock.setTimeout(() => controller.abort(new DOMException("Catalog read timed out.", "TimeoutError")), 10000),
      context, sourceOwner, revisionOwner, position };
    pending[level] = request;
    pages[level] = { ...prior, phase: "loading", error: null, lastRequest: position };
    const current = () => active && !disposed && pending[level] === request && context === request.context
      && (level === "sources" || sourceOwner === request.sourceOwner)
      && (level !== "documents" || revisionOwner === request.revisionOwner);
    if (!publish() || !current()) return;
    let onAbort = () => {};
    const canceled = new Promise((_, reject) => {
      onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      const options = { limit: PAGE_LIMIT, after: position.after, signal: controller.signal };
      const work = level === "sources" ? api.listCatalogSources(options)
        : level === "revisions" ? api.listCatalogRevisions(selectedSource.id, options)
        : api.listCatalogDocuments(selectedSource.id, selectedRevision.commit, options);
      const response = await Promise.race([work, canceled]);
      if (!current()) return;
      const result = parsePage(level, response, position);
      pages[level] = { ...pages[level], ...result, phase: "ready", after: position.after,
        pageNumber: position.pageNumber, error: null };
      if (level === "sources" && selectedSource) {
        const latest = result.items.find((entry) => entry.id === selectedSource.id);
        if (latest) { selectionStale ||= latest.active_commit !== selectedSource.active_commit; selectedSource = latest; }
      }
      publish();
    } catch (error) {
      if (current()) { pages[level] = { ...pages[level], phase: "error", error: failure(error) }; publish(); }
    } finally {
      clock.clearTimeout(request.timer);
      controller.signal.removeEventListener("abort", onAbort);
      if (pending[level] === request) pending[level] = null;
    }
  }
  return {
    async setContext(next) {
      if (disposed || (route === next.route && authenticated === next.authenticated && authGeneration === (next.authGeneration ?? 0))) return;
      clear(); viewFailed = false; authGeneration = next.authGeneration ?? 0; route = next.route; authenticated = next.authenticated;
      active = authenticated && ["runbooks", "policies"].includes(route);
      if (publish() && active) await load("sources");
    },
    load,
    async selectSource(id) {
      if (!active || disposed || viewFailed) return;
      const chosen = pages.sources.items.find((entry) => entry.id === id); if (!chosen) return;
      sourceOwner = {}; revisionOwner = {}; retire("revisions"); retire("documents");
      pages.revisions = initialPage(); pages.documents = initialPage();
      selectedSource = chosen; selectedRevision = null; selectedDocument = null; selectionStale = false;
      if (publish()) await load("revisions");
    },
    async selectRevision(commit) {
      if (!active || disposed || viewFailed) return;
      const chosen = pages.revisions.items.find((entry) => entry.commit === commit); if (!chosen) return;
      revisionOwner = {}; retire("documents"); pages.documents = initialPage();
      selectedRevision = chosen; selectedDocument = null; selectionStale = false;
      if (publish()) await load("documents");
    },
    selectDocument(path) {
      if (!active || disposed || viewFailed) return;
      const chosen = pages.documents.items.find((entry) => entry.path === path); if (!chosen) return;
      selectedDocument = chosen; publish();
    },
    getSnapshot: snapshot,
    dispose() { disposed = true; active = false; clear(); },
  };
}
