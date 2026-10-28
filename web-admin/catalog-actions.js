/** @file Explicit Catalog mutations and bounded observation of durable sync operations; no execution authority. */
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const validId = value => typeof value === "string" && ID.test(value);
const COMMIT = /^[a-f0-9]{40}([a-f0-9]{24})?$/;
const FAILURES = ["fetch_rejected", "fetch_failed", "validation_failed", "limit_exceeded", "cancelled"];

class InvalidCatalogResponse extends Error {}

function parseOperation(value, sourceId, operationId) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join() !== "commit,failure,id,source_id,state"
      || value.id !== operationId || value.source_id !== sourceId
      || !["in_progress", "completed", "failed", "cancelled"].includes(value.state)
      || !(value.commit === null || (typeof value.commit === "string" && COMMIT.test(value.commit)))
      || (value.state === "completed" && value.commit === null)
      || (value.state === "failed" ? !FAILURES.includes(value.failure) : value.failure !== null)) throw new InvalidCatalogResponse();
  return Object.freeze({ id: value.id, source_id: value.source_id, state: value.state, commit: value.commit, failure: value.failure });
}

function guidance(error) {
  return error instanceof InvalidCatalogResponse ? "The Controller response could not be verified."
    : error?.status === 401 ? "Authenticate again before checking the operation."
    : error?.status === 403 ? "Permission denied. Check your Catalog access."
    : error?.status === 404 ? "Operation not found for this source. Check the canonical operation ID returned by Start sync."
    : error?.status ? `The Controller rejected the request (HTTP ${error.status}).`
    : "The Controller could not be reached within the request deadline.";
}

/**
 * Owns abort/deadline/generation for explicit commands and a three-minute sync
 * observation session. A lost POST response is unknown, never an automatic retry.
 * The caller supplies current route/auth and the explicit ready-selection snapshot,
 * renders confirmation, and disposes this owner when the view lifetime ends.
 * @param {{api:object,onChange?:(view:object)=>void,onCommitted?:(action:string)=>void,
 * clock?:{now?:()=>number,setTimeout:Function,clearTimeout:Function}}} options
 */
export function createCatalogActions({ api, onChange = () => {}, onCommitted = () => {}, clock = globalThis }) {
  let contextKey = "", context = {}, observationOwner = {}, active = false, disposed = false, selection = null;
  let mutation = null, read = null, timer = null, totalTimer = null, startedAt = 0, failures = 0;
  let confirmation = null, operation = null, target = null, observation = "idle", message = "", tone = "neutral";
  const now = () => clock.now ? clock.now() : Date.now();
  const snapshot = () => Object.freeze({ active, busy: Boolean(mutation), confirmation, operation, observation, message, tone,
    canResume: active && Boolean(target) && !mutation && ["stopped", "done"].includes(observation) });

  function abort(request) { request?.controller.abort(new DOMException("Catalog view changed.", "AbortError")); }
  function retireRead() { observationOwner = {}; abort(read); read = null; clock.clearTimeout(timer); clock.clearTimeout(totalTimer); timer = null; totalTimer = null; }
  function publish() {
    try { onChange(snapshot()); return true; }
    catch { retireRead(); abort(mutation); mutation = null; active = false; return false; }
  }
  function stop(text) { retireRead(); observation = "stopped"; message = text; tone = "warning"; publish(); }
  async function request(kind, effect) {
    const controller = new AbortController(), owner = context;
    const current = { controller, owner };
    if (kind === "mutation") mutation = current; else read = current;
    const timeout = clock.setTimeout(() => controller.abort(new DOMException("Catalog request timed out.", "TimeoutError")), 10000);
    let onAbort;
    const cancelled = new Promise((_, reject) => {
      onAbort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      return await Promise.race([Promise.resolve().then(() => {
        if (controller.signal.aborted) throw controller.signal.reason;
        return effect(controller.signal);
      }), cancelled]);
    } finally {
      clock.clearTimeout(timeout); controller.signal.removeEventListener("abort", onAbort);
      if (kind === "mutation" && mutation === current) mutation = null;
      if (kind === "read" && read === current) read = null;
    }
  }
  function current(owner) { return active && !disposed && context === owner; }
  function observing() { return ["reading", "waiting"].includes(observation); }

  async function poll(owner, session) {
    const ownsObservation = () => current(owner) && observationOwner === session && observing();
    if (!ownsObservation() || !target) return;
    if (now() - startedAt >= 180000) { stop("Sync observation stopped after three minutes. The last operation state is unchanged; check again to continue."); return; }
    observation = "reading"; if (!publish()) return;
    try {
      const { sourceId, operationId } = target;
      const result = await request("read", signal => api.getCatalogSyncOperation(sourceId, operationId, { signal }));
      if (!ownsObservation()) return;
      operation = parseOperation(result, sourceId, operationId); failures = 0;
      if (operation.state !== "in_progress") {
        retireRead(); observation = "done";
        message = operation.state === "completed" ? `Sync completed at ${operation.commit}. Review the ready revision before activation.`
          : operation.state === "failed" ? `Sync failed (${operation.failure}). This sync did not activate a revision.`
          : "Sync cancelled. This sync did not activate a revision.";
        tone = operation.state === "completed" ? "ok" : "warning"; publish(); return;
      }
      message = "Sync is in progress. Completion does not activate a revision."; tone = "neutral";
    } catch (error) {
      if (!ownsObservation()) return;
      const retryable = !(error instanceof InvalidCatalogResponse) && (!error?.status || error.status >= 500);
      failures++;
      if (!retryable || failures >= 3) { stop(`${guidance(error)} Observation stopped; the operation result is not inferred. Check again explicitly.`); return; }
      message = `${guidance(error)} Retrying the status read only.`; tone = "warning";
    }
    observation = "waiting";
    if (publish()) timer = clock.setTimeout(() => { timer = null; void poll(owner, session); }, failures ? Math.min(1000 * 2 ** failures, 8000) : 1000);
  }
  async function observe(input = target, accepted = false) {
    if (!active || disposed || mutation || !input || !validId(input.sourceId) || !validId(input.operationId)) return;
    retireRead(); target = Object.freeze({ sourceId: input.sourceId, operationId: input.operationId });
    if (operation?.source_id !== target.sourceId || operation?.id !== target.operationId) operation = null;
    const owner = context, session = observationOwner; failures = 0; startedAt = now(); observation = "reading";
    message = accepted ? `Sync accepted as ${target.operationId}. Checking its actual state…`
      : `Checking sync operation ${target.operationId}…`;
    tone = "neutral";
    totalTimer = clock.setTimeout(() => {
      if (current(owner) && observationOwner === session && observing()) stop("Sync observation stopped after three minutes. The last operation state is unchanged; check again to continue.");
    }, 180000);
    await poll(owner, session);
  }
  async function mutate(action, input) {
    const owner = context;
    retireRead(); observation = "idle"; message = `Catalog ${action} request in progress…`; tone = "neutral";
    // request creates the owner synchronously, so publish sees the disabled controls.
    const work = request("mutation", signal => action === "register"
      ? api.registerCatalogSource({ source_id: input.sourceId, url: input.url, reference: input.reference }, { signal })
      : action === "sync" ? api.startCatalogSync(input.sourceId, { operation_id: input.operationId }, { signal })
      : api.activateCatalogRevision(input.sourceId, { commit: input.commit }, { signal }));
    publish();
    try {
      const result = await work; if (!current(owner)) return;
      if (action === "sync") {
        if (!result || !validId(result.id) || result.source_id !== input.sourceId || result.state !== "in_progress") throw new InvalidCatalogResponse();
        operation = null;
        await observe({ sourceId: input.sourceId, operationId: result.id }, true);
      } else {
        if (!result || result.id !== input.sourceId || (action === "activate" && result.active_commit !== input.commit)) throw new InvalidCatalogResponse();
        message = action === "activate" ? `Revision ${input.commit} activated for ${input.sourceId}.` : `Source ${input.sourceId} registered.`;
        tone = "ok"; publish();
        try { onCommitted(action); }
        catch { message += " Refresh Catalog metadata to review the change."; publish(); }
      }
    } catch (error) {
      if (!current(owner)) return;
      const knownRejection = Number.isInteger(error?.status) && error.status >= 400 && error.status < 500;
      message = knownRejection ? `${guidance(error)} No automatic retry was sent.`
        : "Request outcome unknown. It may already have been accepted. No automatic retry was sent; verify the source or operation before submitting again.";
      if (action === "sync") { target = Object.freeze({ sourceId: input.sourceId, operationId: input.operationId }); operation = null; observation = "stopped"; }
      tone = "warning"; publish();
    }
  }
  return {
    getSnapshot: snapshot,
    setContext(next) {
      if (disposed) return;
      const nextSelection = next.selection || null;
      const key = JSON.stringify([next.route, next.authenticated, next.authGeneration ?? 0, nextSelection]);
      if (key === contextKey) return;
      contextKey = key; context = {}; retireRead(); abort(mutation); mutation = null;
      active = Boolean(next.authenticated) && ["runbooks", "policies"].includes(next.route); selection = nextSelection;
      confirmation = null; operation = null; target = null; observation = "idle"; message = ""; tone = "neutral"; publish();
    },
    async submit(action, input) {
      if (!active || disposed || mutation || confirmation || observing()) return;
      if (!validId(input.sourceId)) { message = "Enter a valid source ID."; tone = "warning"; publish(); return; }
      if (action === "activate") {
        if (!selection || selection.sourceId !== input.sourceId || selection.commit !== input.commit
            || selection.state !== "ready" || selection.stale || !COMMIT.test(input.commit)) {
          message = "Select and review the same source and ready revision before activation."; tone = "warning"; publish(); return;
        }
        confirmation = Object.freeze({ sourceId: input.sourceId, commit: input.commit, activeCommit: selection.activeCommit }); publish(); return;
      }
      if (action === "sync" && validId(input.operationId)) await mutate(action, input);
      else if (action === "register" && input.url && input.reference) await mutate(action, input);
      else { message = "Enter the required Catalog action fields."; tone = "warning"; publish(); }
    },
    cancelActivation() { confirmation = null; publish(); },
    async confirmActivation() {
      if (!active || !confirmation || mutation || disposed) return;
      const input = confirmation; confirmation = null; await mutate("activate", input);
    },
    resumeSync: input => observe(input),
    stopObservation() { if (observing()) stop("Sync observation stopped. The operation continues on the Controller; check again when ready."); },
    dispose() { disposed = true; active = false; context = {}; retireRead(); abort(mutation); mutation = null; confirmation = null; operation = null; target = null; },
  };
}
