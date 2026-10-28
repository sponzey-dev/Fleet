/** @file Owns immutable Catalog Job review, preview and explicit submission; canonical state stays on the Controller. */
const COMMIT = /^[a-f0-9]{40}([a-f0-9]{24})?$/;
const CHECKSUM = /^[a-f0-9]{64}$/;
const text = value => typeof value === "string" && value.length > 0;
class InvalidCatalogJobResponse extends Error {}
function referenceFrom(value) {
  if (!value || !text(value.sourceId) || !text(value.commit) || !COMMIT.test(value.commit) || !text(value.path)
      || !text(value.checksum) || !CHECKSUM.test(value.checksum) || value.kind !== "runbook" || value.state !== "ready"
      || value.activeCommit !== value.commit || value.stale) return null;
  return Object.freeze({ source_id: value.sourceId, commit: value.commit, path: value.path, checksum: value.checksum });
}
function detailBody(value, reference) {
  if (!value || value.kind !== "runbook" || value.path !== reference.path || value.checksum !== reference.checksum
      || typeof value.body !== "string" || !value.body.length || new TextEncoder().encode(value.body).length > 1048576) throw new InvalidCatalogJobResponse();
  return value.body;
}
function parsePreview(value) {
  const counts = ["matched_count", "selected_count", "disabled_count", "offline_count"];
  if (!value || !Array.isArray(value.agents) || !Array.isArray(value.warnings)
      || counts.some(key => !Number.isSafeInteger(value[key]) || value[key] < 0)
      || value.agents.length !== value.matched_count) throw new InvalidCatalogJobResponse();
  const seen = new Set(), ids = [];
  let disabled = 0, offline = 0;
  for (const agent of value.agents) {
    if (!agent || !text(agent.agent_id) || seen.has(agent.agent_id) || typeof agent.selected_for_dispatch !== "boolean"
        || !["online", "offline", "disabled", "pending", "busy", "degraded"].includes(agent.status) || !text(agent.name) || !Array.isArray(agent.labels)) throw new InvalidCatalogJobResponse();
    seen.add(agent.agent_id);
    if (agent.status === "disabled") disabled++;
    if (agent.status === "offline") offline++;
    if (agent.selected_for_dispatch) {
      if (agent.status === "disabled") throw new InvalidCatalogJobResponse();
      ids.push(agent.agent_id);
    }
  }
  if (!ids.length || ids.length !== value.selected_count || disabled !== value.disabled_count || offline !== value.offline_count) throw new InvalidCatalogJobResponse();
  // Keep only product-safe preview metadata, not arbitrary response properties.
  return Object.freeze({ ids: Object.freeze(ids), matched: value.matched_count, disabled, offline,
    agents: Object.freeze(value.agents.map(a => Object.freeze({ id: a.agent_id, name: a.name, status: a.status, selected: a.selected_for_dispatch }))) });
}
function parseCreated(value, intent) {
  if (!value || value.job_id !== intent.body.job_id || value.target_count !== intent.body.target_agent_ids.length
      || value.assignment_count !== value.target_count || !["queued", "pending_approval"].includes(value.status)
      || (value.status === "pending_approval" ? !text(value.approval_request_id) : value.approval_request_id !== null)) throw new InvalidCatalogJobResponse();
  return Object.freeze({ job_id: value.job_id, status: value.status, approval_request_id: value.approval_request_id });
}
function guidance(error) {
  return error instanceof InvalidCatalogJobResponse ? "The Controller response could not be verified."
    : error?.status === 401 ? "Authenticate again before continuing."
    : error?.status === 403 ? "Permission denied. Check your Job and Catalog access."
    : error?.status === 409 ? "The selection or target state changed. Refresh and review before preparing another Job."
    : error?.status === 404 ? "The selected record was not found. Refresh and review the selection."
    : error?.status === 400 ? "The Controller rejected this selection or its options."
    : "The Controller could not be reached within the request deadline.";
}

/** Owns one bounded review and at most one unresolved Job intent; no mutation is automatically retried. */
export function createCatalogJobSubmission({ api, onChange = () => {}, onCreated = () => {}, clock = globalThis,
  makeJobId = () => `job-catalog-ui-${globalThis.crypto.randomUUID()}` }) {
  let authGeneration = 0, intentGeneration = 0;
  let route = "", authenticated = false, disposed = false, contextKey = "", owner = {};
  let reference = null, selector = "", confirmed = false, body = "", preview = null, intent = null;
  let pending = null, phase = "idle", message = "Choose an active, ready Runbook and enter a target selector.", result = null;
  const active = () => !disposed && authenticated && route === "runbooks";
  const eligible = () => active() && Boolean(reference);
  const busy = () => Boolean(pending) || ["reading", "submitting", "checking"].includes(phase);
  const sameReference = (left, right) => left && right && ["source_id", "commit", "path", "checksum"].every(k => left[k] === right[k]);
  const snapshot = () => Object.freeze({ phase, message, body, preview, reference, selector, confirmed, result,
    submittedReference: intent?.reference || null, submittedTargetIds: intent?.body.target_agent_ids || null,
    jobId: intent?.body.job_id || "", active: active(), eligible: eligible(), busy: busy(),
    canPreview: eligible() && Boolean(selector) && !busy() && !intent,
    canSubmit: eligible() && phase === "prepared" && confirmed && !pending && !intent,
    canReconcile: active() && Boolean(intent) && !pending && ["unknown", "missing", "conflict"].includes(phase),
    canRetry: active() && phase === "missing" && Boolean(intent) && !pending && intentGeneration === authGeneration,
    canReset: !busy() && (!intent || phase === "created" || phase === "conflict") });
  function publish() {
    try { onChange(snapshot()); } catch { disposed = true; pending?.controller.abort(); pending = null; }
  }
  function invalidate() {
    owner = {}; pending?.controller.abort(new DOMException("Catalog Job view changed.", "AbortError")); pending = null;
    if (intent && phase === "submitting") phase = "unknown";
    body = ""; preview = null; confirmed = false;
    if (!intent) phase = "idle";
    else if (phase === "checking") phase = "unknown";
    message = intent && phase !== "created" ? `Submission outcome unknown for ${intent.body.job_id}. Check that Job ID before trying again.`
      : "Review the active Runbook and target selector before creating a Job.";
  }
  async function request(effect) {
    if (!active()) throw new DOMException("Catalog Job owner is inactive.", "AbortError");
    const controller = new AbortController(), current = { controller };
    pending = current;
    const deadline = clock.setTimeout(() => controller.abort(new DOMException("Catalog Job request timed out.", "TimeoutError")), 10000);
    let abort;
    const cancelled = new Promise((_, reject) => { abort = () => reject(controller.signal.reason); controller.signal.addEventListener("abort", abort, { once: true }); });
    try {
      return await Promise.race([Promise.resolve().then(() => { controller.signal.throwIfAborted(); return effect(controller.signal); }), cancelled]);
    } finally {
      clock.clearTimeout(deadline); controller.signal.removeEventListener("abort", abort);
      if (pending === current) pending = null;
    }
  }
  const current = token => active() && owner === token;
  async function complete(value) {
    const token = owner;
    result = value; phase = "created"; message = value.status === "pending_approval"
      ? `Created Job ${value.job_id} with an approval request${value.approval_request_id ? ` ${value.approval_request_id}` : ""}. Use Approvals for pending requests and Selected job for the current result.`
      : `Job ${value.job_id} is available in the shared results view.`;
    publish();
    if (current(token)) {
      try { await request(signal => onCreated(value, { signal })); }
      catch { if (current(token)) { message = `Job ${value.job_id} was recorded. Open it in the shared results view.`; publish(); } }
    }
  }
  async function send(token) {
    phase = "submitting"; message = `Submitting ${intent.body.job_id}.`; publish();
    try {
      const response = await request(signal => api.createCatalogRunbookJob(intent.body, { signal }));
      if (!current(token)) return;
      await complete(parseCreated(response, intent));
    } catch (error) {
      if (!current(token)) return;
      if (error?.status && ([400, 401, 403, 404].includes(error.status)
          || (error.status === 409 && error.catalogRejected === true))) {
        intent = null; phase = "error"; body = ""; preview = null; confirmed = false; message = guidance(error);
      } else { phase = "unknown"; message = `${guidance(error)} Outcome unknown for ${intent.body.job_id}; check that Job ID. No automatic retry.`; }
      publish();
    }
  }
  return {
    getSnapshot: snapshot,
    setContext(next) {
      if (disposed) return;
      const key = JSON.stringify([next.route, Boolean(next.authenticated), next.authGeneration ?? 0, next.selection || null]);
      if (key === contextKey) return;
      contextKey = key; invalidate(); authGeneration = next.authGeneration ?? 0; route = next.route; authenticated = Boolean(next.authenticated); reference = referenceFrom(next.selection); publish();
    },
    setSelector(value) {
      const next = String(value ?? "").trim(); if (next === selector || disposed) return;
      invalidate(); selector = next; publish();
    },
    setConfirmed(value) { if (disposed) return; confirmed = Boolean(value); publish(); },
    async preview() {
      if (!snapshot().canPreview) return;
      const token = owner, selected = reference, selectedSelector = selector;
      phase = "reading"; message = "Reading the selected Runbook and resolving targets..."; confirmed = false; body = ""; preview = null; publish();
      try {
        const document = await request(signal => api.getCatalogDocumentDetail(selected.source_id, selected.commit, selected.path, { signal }));
        if (!current(token)) return;
        const reviewedBody = detailBody(document, selected);
        const targets = await request(signal => api.previewSelector({ selector: selectedSelector }, { signal }));
        if (!current(token)) return;
        preview = parsePreview(targets); body = reviewedBody; phase = "prepared";
        message = `Review the exact Runbook and ${preview.ids.length} selected Agent(s), then confirm creation. Disabled Agents are excluded; offline Agents may wait for reconnection.`;
      } catch (error) { if (!current(token)) return; phase = "error"; body = ""; preview = null; message = guidance(error); }
      publish();
    },
    async submit() {
      if (!snapshot().canSubmit) return;
      const id = makeJobId(); if (!text(id)) return;
      intentGeneration = authGeneration;
      intent = Object.freeze({ reference, selector, body: Object.freeze({ job_id: id, ...reference,
        target_agent_ids: Object.freeze([...preview.ids]), timeout_seconds: 30, expires_in_seconds: 300, confirmed_high_risk: true }) });
      await send(owner);
    },
    async reconcile() {
      if (!snapshot().canReconcile) return;
      const token = owner, selected = intent; phase = "checking"; message = `Checking stored Job ${selected.body.job_id}...`; publish();
      try {
        const job = await request(signal => api.getJob(selected.body.job_id, { signal }));
        if (!current(token)) return;
        const ids = job?.target_agent_ids;
        if (job?.id !== selected.body.job_id || typeof job.status !== "string" || !sameReference(job.catalog_provenance, selected.reference)
            || !Array.isArray(ids) || ids.length !== selected.body.target_agent_ids.length || new Set(ids).size !== ids.length
            || !ids.every(id => selected.body.target_agent_ids.includes(id))) throw new InvalidCatalogJobResponse();
        await complete(Object.freeze({ job_id: job.id, status: job.status, approval_request_id: null }));
      } catch (error) {
        if (!current(token)) return;
        phase = error?.status === 404 ? "missing" : error instanceof InvalidCatalogJobResponse ? "conflict" : "unknown";
        message = error?.status === 404 ? `No stored Job ${selected.body.job_id} was found. Check again or explicitly retry its original document and Agent IDs with the same Job ID; a new ID will not be generated.`
          : `${guidance(error)} The original Job ID remains ${selected.body.job_id}.`;
        if (intentGeneration !== authGeneration) message = "Authentication changed. Check stored Job " + selected.body.job_id + "; this submission cannot be replayed.";
        publish();
      }
    },
    async retry() { if (snapshot().canRetry) await send(owner); },
    reset() { if (!snapshot().canReset) return; intent = null; result = null; invalidate(); publish(); },
    dispose() { if (disposed) return; invalidate(); disposed = true; reference = null; intent = null; result = null; },
  };
}
