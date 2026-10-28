/** @file Job observation ownership, separate from DOM effects and canonical server state. */
import { ApiHttpError } from "./api-client.js";
import { OutputReadError } from "./job-output-reader.js";

/** @typedef {Record<string, unknown> & { id: string, status: string }} ObservedJob */
/** @typedef {{ kind: string, status: number | null, retryable: boolean }} ObservationError */
/** @typedef {{ phase: string, jobId: string, job: ObservedJob | null, chunks: readonly unknown[], output:Readonly<import('./job-output-reader.js').OutputReadSnapshot>|null, lastUpdatedAt: number | null, retryAt: number | null, error: Readonly<ObservationError> | null, attempt: number }} ObservationSnapshot */
/** @typedef {{ now: () => number, setTimeout: (callback: () => void, delay: number) => number, clearTimeout: (id: number) => void }} ObserverClock */
/** @typedef {{ getJob: (id: string, options: { signal: AbortSignal }) => Promise<unknown>, getJobOutput: (id: string, options: { signal: AbortSignal }) => Promise<unknown> }} JobReadApi */

const POLL_INTERVAL_MS = 1000;
const REQUEST_TIMEOUT_MS = 10000;
const RETRY_DELAYS_MS = Object.freeze([1000, 2000, 4000]);
/** @type {ObserverClock} */
const browserClock = {
  now: () => Date.now(),
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: (id) => globalThis.clearTimeout(id),
};

class InvalidObservationResponse extends Error {}

/** Validates the selected Job read without inferring canonical state from output. @param {unknown} value @param {string} jobId @returns {ObservedJob} */
export function parseObservedJob(value, jobId) {
  if (!value || typeof value !== "object" || !("id" in value) || value.id !== jobId || !("status" in value) || typeof value.status !== "string") throw new InvalidObservationResponse();
  return /** @type {ObservedJob} */ (value);
}

/** Classifies safe read failures without preserving a body, cursor or raw error. @param {unknown} error @param {{outputPage?:boolean}} options @returns {Readonly<ObservationError>} */
export function classifyJobReadFailure(error, { outputPage = false } = {}) {
  if (error instanceof ApiHttpError) {
    const status = error.status;
    const kind = status === 401 ? "authentication"
      : status === 403 ? "forbidden"
      : status === 404 ? "not_found"
      : outputPage && status === 409 ? "output_stale" : outputPage && status === 413 ? "output_limit" : outputPage && status === 400 ? "output_query" : "http";
    return Object.freeze({ kind, status, retryable: status === 408 || status === 429 || status >= 500 });
  }
  if (error instanceof OutputReadError) {
    const kind = error.kind === "stale" ? "output_stale" : error.kind === "conflict" ? "output_conflict" : error.kind === "gap" ? "output_gap" : "invalid_response";
    return Object.freeze({ kind, status: null, retryable: false });
  }
  if (error instanceof InvalidObservationResponse || error instanceof SyntaxError) {
    return Object.freeze({ kind: "invalid_response", status: null, retryable: false });
  }
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return Object.freeze({ kind: "timeout", status: null, retryable: true });
  }
  if (error instanceof TypeError || (error instanceof DOMException && error.name === "NetworkError")) {
    return Object.freeze({ kind: "network", status: null, retryable: true });
  }
  return Object.freeze({ kind: "unexpected", status: null, retryable: false });
}

/**
 * Owns one selected Job's read requests and timer. Selection, pause and disposal
 * abort the previous generation; late API settlements cannot publish a snapshot.
 * Terminal classification is supplied by the existing UI/server contract, not
 * inferred from output. An injected page reader drains at most four pages before
 * an owned timer yields; completion requires fresh detail and an open empty read
 * after the stored prefix is drained. Without that adapter, the original full-
 * array library effect remains available; page failures never select it.
 * Listener failures stop observation with a safe local view error, never retry.
 * @param {{ api: JobReadApi, isTerminal: (job: ObservedJob) => boolean, onChange: (snapshot: Readonly<ObservationSnapshot>) => void, clock?: ObserverClock, outputReader?:ReturnType<typeof import('./job-output-reader.js').createJobOutputReader> }} options
 */
export function createJobObserver({ api, isTerminal, onChange, clock = browserClock, outputReader }) {
  /** @type {Readonly<ObservationSnapshot>} */
  let snapshot = Object.freeze({ phase: "idle", jobId: "", job: null, chunks: [], output: null, lastUpdatedAt: null, retryAt: null, error: null, attempt: 0 });
  let generation = 0;
  let disposed = false;
  let failures = 0;
  let terminalCandidate = false;
  /** @type {number | null} */
  let timer = null;
  /** @type {{ controller: AbortController, deadline: number } | null} */
  let activeRead = null;

  function invalidate() {
    generation += 1;
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
    if (activeRead) {
      clock.clearTimeout(activeRead.deadline);
      activeRead.controller.abort();
    }
    activeRead = null;
    terminalCandidate = false;
  }

  /** @param {Partial<ObservationSnapshot>} patch */
  function publish(patch) {
    snapshot = Object.freeze({ ...snapshot, ...patch });
    try {
      onChange(snapshot);
    } catch {
      invalidate();
      snapshot = Object.freeze({ ...snapshot, phase: "error", retryAt: null, error: Object.freeze({ kind: "view", status: null, retryable: false }) });
    }
  }

  /** @param {number} owner */
  function current(owner) {
    return !disposed && owner === generation;
  }

  /** @param {number} owner @param {string} jobId */
  async function poll(owner, jobId) {
    if (!current(owner)) return;
    const controller = new AbortController();
    const { signal } = controller;
    const deadline = clock.setTimeout(() => controller.abort(new DOMException("Job read timed out.", "TimeoutError")), REQUEST_TIMEOUT_MS);
    const request = { controller, deadline };
    activeRead = request;
    let outputPageRead = false;
    let onAbort = () => {};
    /** @type {Promise<never>} */
    const canceled = new Promise((_, reject) => {
      onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
    });
    const read = (async () => {
      const value = await api.getJob(jobId, { signal });
      signal.throwIfAborted();
      const job = parseObservedJob(value, jobId);
      outputPageRead = Boolean(outputReader);
      const output = outputReader ? await outputReader.read(jobId, { signal }) : null;
      const chunks = output ? output.fragments : await api.getJobOutput(jobId, { signal });
      signal.throwIfAborted();
      if (!Array.isArray(chunks)) throw new InvalidObservationResponse();
      return { job, chunks, output };
    })();
    /** @type {number | null} */
    let nextDelay = null;
    try {
      const result = await Promise.race([read, canceled]);
      if (!current(owner)) return;
      const serverTerminal = isTerminal(result.job);
      const candidate = Boolean(result.output && serverTerminal && result.output.caughtUp && result.output.jobStatus === result.job.status);
      const terminal = result.output
        ? candidate && terminalCandidate && result.output.startedOpen && result.output.empty
        : serverTerminal;
      terminalCandidate = candidate;
      failures = 0;
      publish({ phase: terminal ? "completed" : "following", job: result.job, chunks: result.chunks, output: result.output, lastUpdatedAt: clock.now(), retryAt: null, error: null, attempt: snapshot.attempt + 1 });
      if (!terminal) nextDelay = result.output && (!result.output.caughtUp || candidate) ? 0 : POLL_INTERVAL_MS;
    } catch (error) {
      if (!current(owner)) return;
      terminalCandidate = false;
      const failure = classifyJobReadFailure(error, { outputPage: outputPageRead });
      nextDelay = failure.retryable ? RETRY_DELAYS_MS[failures] ?? null : null;
      failures += 1;
      publish({ phase: "error", error: failure, retryAt: nextDelay === null ? null : clock.now() + nextDelay, attempt: snapshot.attempt + 1 });
    } finally {
      clock.clearTimeout(deadline);
      signal.removeEventListener("abort", onAbort);
      if (activeRead === request) activeRead = null;
    }
    if (current(owner) && nextDelay !== null) {
      timer = clock.setTimeout(() => {
        timer = null;
        void poll(owner, jobId);
      }, nextDelay);
    }
  }

  function requireActive() {
    if (disposed) throw new Error("Job observer is disposed.");
  }

  function resume() {
    requireActive();
    if (!snapshot.jobId) return;
    invalidate();
    const owner = generation;
    failures = 0;
    const restartOutput = Boolean(outputReader && (snapshot.phase === "completed" || (snapshot.error && !snapshot.error.retryable)));
    if (restartOutput) outputReader?.reset(snapshot.jobId);
    publish({ phase: "loading", error: null, retryAt: null, ...(restartOutput ? { chunks: [], output: null } : {}) });
    if (current(owner)) void poll(owner, snapshot.jobId);
  }

  return {
    /** Selects even the same ID afresh; cached terminal state never skips a server read. @param {string} jobId */
    select(jobId) {
      requireActive();
      const id = String(jobId).trim();
      if (!id) throw new Error("A Job ID is required.");
      invalidate();
      const owner = generation;
      failures = 0;
      outputReader?.reset(id);
      publish({ phase: "loading", jobId: id, job: null, chunks: [], output: null, lastUpdatedAt: null, retryAt: null, error: null, attempt: 0 });
      if (current(owner)) void poll(owner, id);
    },
    /** Cancels pending effects but preserves the last server snapshot for reading. */
    pause() {
      if (disposed || !snapshot.jobId) return;
      invalidate();
      publish({ phase: "paused", error: null, retryAt: null });
    },
    resume,
    /** Permanently releases the owner; repeated disposal is harmless. */
    dispose() {
      if (disposed) return;
      disposed = true;
      invalidate();
      outputReader?.dispose();
      publish({ phase: "disposed", chunks: [], output: null, retryAt: null });
    },
    getSnapshot: () => snapshot,
  };
}
