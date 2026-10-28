/** @file Static Admin views and explicit API effects; observation never writes Job state. */
import { createApiClient, normalizeAdminToken } from "./api-client.js";
import { createAdminAccounts } from "./admin-accounts.js";
import { createJobObserver, classifyJobReadFailure, parseObservedJob } from "./job-observer.js";
import { createJobOutputReader } from "./job-output-reader.js";
import { createCatalogExplorer } from "./catalog-explorer.js";
import { createCatalogActions } from "./catalog-actions.js";
import { createCatalogJobSubmission } from "./catalog-job.js";

const state = {
  token: "",
  agents: [],
  policies: [],
  remediations: [],
  selectedAgentId: "",
  selectedPolicyId: "",
  selectedRemediationId: "",
  createdEnrollmentToken: null,
  metricsWindowMs: 5 * 60 * 1000,
  auditCursor: "",
  auditItems: [],
};

const ADMIN_ROUTES = new Set([
  "overview",
  "agents",
  "run",
  "runbooks",
  "policies",
  "remediations",
  "audit",
  "settings",
]);

const ADMIN_ROUTE_ALIASES = { approvals: "run", jobs: "run" };

const ADMIN_ROUTE_PRESENTATION = {
  overview: ["Overview", "Live operational state from the Controller — no inferred health."],
  agents: ["Agents", "Inventory, facts, metrics, and the most recent agent activity."],
  run: ["Run", "Create signed commands, review pending approvals, and inspect assignment state."],
  runbooks: ["Runbooks", "Create signed runbook jobs and review pending approvals."],
  policies: ["Policies & Drift", "Manage policy sources, assignments, and observed drift."],
  remediations: ["Remediations", "Approve policy-driven fixes through their persisted lifecycle."],
  audit: ["Audit", "Review durable product and security events."],
  settings: ["Settings", "Your account, people, enrollment and Controller signing trust."],
};

const DEFAULT_TELEMETRY_WINDOW_MS = 5 * 60 * 1000;
const TELEMETRY_PAGE_LIMIT = 120;
const DETAIL_PAGE_LIMIT = 25;
const JOB_OUTPUT_POLL_ATTEMPTS = 45;
const COMMAND_JOB_EXPIRES_IN_SECONDS = 300;
const TERMINAL_DISPATCH_STATES = new Set(["completed", "partial_success", "failed", "expired", "rejected", "canceled"]);
const TERMINAL_JOB_STATUSES = new Set(["success", "partial_success", "failed", "expired", "canceled"]);

const api = createApiClient({
  tokenProvider: () => state.token,
  formatError: formatApiError,
  onUnauthorized: () => { adminAccounts.expire(); },
});

const adminAccounts = createAdminAccounts({ api, onChange: onAccountState, onOnce: showOnceSecret, onInvalidate: clearOnceSecret });

const directSubmissions = Object.fromEntries(["command", "runbook"].map(kind => [kind, createDirectJobSubmission({
  createJob: (body, options) => kind === "command" ? api.createCommandJob(body, options) : api.createRunbookJob(body, options),
  getJob: (id, options) => api.getJob(id, options),
  onChange: view => renderDirectSubmission(kind, view),
})]));

const jobObservation = typeof document !== "undefined" && document.querySelector("#job-output")
  ? createJobObservationPanel({
      apiClient: api,
      outputReaderFactory: () => createJobOutputReader({ api }),
      elements: {
        status: document.querySelector("#job-observation-status"),
        lastUpdated: document.querySelector("#job-last-updated"),
        pause: document.querySelector("#pause-job-observation"),
        resume: document.querySelector("#resume-job-observation"),
        output: document.querySelector("#job-output"),
        targets: document.querySelector("#job-targets"),
        artifacts: document.querySelector("#job-artifacts"),
        provenance: document.querySelector("#job-catalog-provenance"),
        history: document.querySelector("#browse-job-output"),
        nextPage: document.querySelector("#next-job-output-page"),
        outputInfo: document.querySelector("#job-output-info"),
      },
    })
  : null;

const catalogPanel = typeof document !== "undefined" && document.querySelector("#catalog-list")
  ? createCatalogPanel({ apiClient: api, onJobCreated: async (job, { signal }) => {
      jobObservation?.select(job.job_id);
      const token = state.token;
      const [jobs, approvals] = await Promise.all([api.listJobs({ signal }), api.listApprovals("pending", { signal })]);
      signal.throwIfAborted();
      if (state.token !== token || currentAdminRoute() !== "runbooks") return;
      document.querySelector("#jobs-list").innerHTML = renderJobs(jobs);
      document.querySelector("#approvals-list").innerHTML = renderApprovals(approvals, jobs);
      wireApprovalButtons();
    }, elements: {
      selection: document.querySelector("#catalog-selection"),
      execution: Object.fromEntries(["panel", "reference", "selector", "preview", "body", "confirm", "review", "submit", "check", "retry", "reset", "status"]
        .map(key => [key, document.querySelector(`#catalog-job-${key}`)])),
      actions: {
        form: document.querySelector("#catalog-action-form"),
        status: document.querySelector("#catalog-action-status"), operation: document.querySelector("#catalog-operation-status"),
        check: document.querySelector("#check-catalog-sync"), stop: document.querySelector("#stop-catalog-sync"), resume: document.querySelector("#resume-catalog-sync"),
        dialog: document.querySelector("#catalog-activation-dialog"), details: document.querySelector("#catalog-activation-details"),
        confirm: document.querySelector("#confirm-catalog-activation"), cancel: document.querySelector("#cancel-catalog-activation"),
        fields: Object.fromEntries([["sourceId", "source-id"], ["operationId", "operation-id"], ["url", "url"], ["reference", "reference"], ["commit", "commit"]]
          .map(([key, id]) => [key, document.querySelector(`#catalog-${id}`)])),
      },
      ...Object.fromEntries(["sources", "revisions", "documents"].map(level => [level, {
        list: document.querySelector(level === "sources" ? "#catalog-list" : `#catalog-${level}`),
        ...Object.fromEntries(["status", "first", "next", "retry"].map(action => [action, document.querySelector(`#catalog-${level}-${action}`)])),
      }])),
    } })
  : null;

function currentAdminRoute() {
  const route = globalThis.location?.hash?.slice(1).toLowerCase() || "overview";
  const canonicalRoute = ADMIN_ROUTE_ALIASES[route] || route;
  return ADMIN_ROUTES.has(canonicalRoute) ? canonicalRoute : "overview";
}

/// Applies a hash route without persisting token or view state in browser storage.
export function applyAdminRoute({ focus = false } = {}) {
  if (typeof document === "undefined") {
    return "overview";
  }
  const route = currentAdminRoute();
  document.querySelectorAll("[data-route]").forEach((element) => {
    element.hidden = !element.dataset.route.split(" ").includes(route);
  });
  document.querySelectorAll("[data-route-link]").forEach((link) => {
    const active = link.dataset.routeLink === route;
    link.classList.toggle("active", active);
    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
  const [title, subtitle] = ADMIN_ROUTE_PRESENTATION[route];
  const pageTitle = document.querySelector("#page-title");
  const pageSubtitle = document.querySelector("#page-subtitle");
  if (pageTitle) pageTitle.textContent = title;
  if (pageSubtitle) pageSubtitle.textContent = subtitle;
  if (focus) {
    document.querySelector(`[data-route-focus="${route}"]`)?.focus({ preventScroll: true });
  }
  for (const submission of Object.values(directSubmissions)) submission.setContext(adminViewContext(route));
  jobObservation?.setContext(adminViewContext(route));
  void catalogPanel?.setContext(adminViewContext(route));
  return route;
}

/**
 * Composes the tested read owner with the shared result panel. Route/auth changes
 * release requests; returning reads the server afresh. View tokens also isolate
 * artifact reads from a later selection, including re-selection of the same ID.
 * Artifact inspection pauses Job observation and has its own bounded read, which
 * is canceled on selection/context change or explicit resume. Missing artifact
 * bodies are reported as unavailable, not as completed Job output.
 * A focused control becoming disabled hands focus to its enabled counterpart;
 * updates never move focus from another reading or input position.
 * @param {{ apiClient: import('./job-observer.js').JobReadApi & { getJobArtifact?: (jobId: string, artifactId: string, options: {signal: AbortSignal}) => Promise<unknown> }, elements: { status: HTMLElement, lastUpdated: HTMLElement, pause: HTMLButtonElement, resume: HTMLButtonElement, output: HTMLElement, targets: HTMLElement, artifacts: HTMLElement, history?:HTMLButtonElement, nextPage?:HTMLButtonElement, outputInfo?:HTMLElement, provenance?:HTMLElement }, clock?: import('./job-observer.js').ObserverClock, outputReaderFactory?:()=>ReturnType<typeof createJobOutputReader> }} options
 */
export function createJobObservationPanel({ apiClient, elements, outputReaderFactory, clock = {
  now: () => Date.now(),
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: (id) => globalThis.clearTimeout(id),
} }) {
  /** @type {ReturnType<typeof createJobObserver> | null} */
  let owner = null;
  /** @type {Readonly<{ jobId: string }> | null} */
  let selection = null;
  let route = "";
  let authenticated = false;
  let authGeneration = 0;
  let disposed = false;
  let renderedJobId = "";
  /** @type {{ controller: AbortController, deadline: number } | null} */
  let artifactRead = null;
  /** @typedef {{selection:Readonly<{jobId:string}>, reader:ReturnType<typeof createJobOutputReader>, page:number, canNext:boolean, snapshot:Readonly<import('./job-observer.js').ObservationSnapshot>|null, failures:number, timer:number|null}} HistoryView */
  /** @type {HistoryView|null} */
  let history = null;
  /** @type {{controller:AbortController,deadline:number,view:HistoryView}|null} */
  let historyRead = null;
  const active = () => !disposed && authenticated && (route === "run" || route === "runbooks");

  function release() {
    cancelArtifactRead();
    cancelHistory();
    const previous = owner;
    owner = null;
    previous?.dispose();
  }

  function cancelHistory() {
    const view = history;
    history = null;
    if (view?.timer !== null && view?.timer !== undefined) clock.clearTimeout(view.timer);
    view?.reader.dispose();
    if (view) { view.timer = null; view.snapshot = null; }
    const previous = historyRead;
    historyRead = null;
    if (previous) { clock.clearTimeout(previous.deadline); previous.controller.abort(); }
  }

  function cancelArtifactRead() {
    const previous = artifactRead;
    artifactRead = null;
    if (previous) {
      clock.clearTimeout(previous.deadline);
      previous.controller.abort();
    }
  }

  /** @param {HTMLElement} element @param {string} text */
  function writeText(element, text) {
    if (element.textContent !== text) element.textContent = text;
  }

  /** @param {HTMLElement} element @param {string} html */
  function writeHtml(element, html) {
    if (element.innerHTML !== html) element.innerHTML = html;
  }

  function renderIdle() {
    renderedJobId = "";
    writeText(elements.status, "Select a job to observe.");
    writeText(elements.lastUpdated, "Last successful update: Not yet.");
    writeText(elements.output, "Run a command or select a job to view output.");
    writeHtml(elements.targets, renderJobTargetTable(null));
    writeHtml(elements.artifacts, renderJobArtifacts(null));
    if (elements.provenance) writeText(elements.provenance, "Select a Job to inspect its document provenance.");
    elements.pause.disabled = true;
    elements.resume.disabled = true;
    if (elements.history) { elements.history.disabled = true; elements.history.hidden = !outputReaderFactory; }
    if (elements.nextPage) { elements.nextPage.disabled = true; elements.nextPage.hidden = !outputReaderFactory; }
    if (elements.outputInfo) { elements.outputInfo.hidden = !outputReaderFactory; writeText(elements.outputInfo, "Select a job to read stored output."); }
  }

  /** @param {Readonly<import('./job-observer.js').ObservationError>} error */
  function failureGuidance(error) {
    return error.kind === "authentication" ? "Please authenticate again with an admin token."
      : error.kind === "forbidden" ? "Permission denied. Check your access before retrying."
      : error.kind === "not_found" ? "Job not found. Refresh history or select another job."
      : error.kind === "output_stale" ? "Stored output changed after retention or restore. Reopen stored history to read again."
      : error.kind === "output_limit" ? "An output entry exceeds this read's metadata limit. The entry was not skipped."
      : error.kind === "output_query" ? "The stored output read position is invalid. Reopen the job to read again."
      : error.kind === "output_conflict" || error.kind === "output_gap" ? "Stored output could not be reconciled with the previous read. Reopen stored history before continuing."
      : "The latest job read failed. The last server result is unchanged.";
  }

  /** @param {Readonly<import('./job-observer.js').ObservationSnapshot>} snapshot */
  function render(snapshot) {
    const { phase, job, jobId, chunks, output, lastUpdatedAt, error, retryAt } = snapshot;
    const historyMode = Boolean(history && history.snapshot === snapshot);
    const focusedControl = elements.pause.ownerDocument?.activeElement;
    let description = phase === "loading" ? "Loading job from the Controller."
      : phase === "paused" ? "Observation paused. Pausing observation does not cancel the job."
      : phase === "completed" ? `Observation complete. Server result: ${job?.status || "unknown"}.`
      : "Following job. Pausing observation does not cancel the job.";
    if (historyMode) description = phase === "history_loading" ? "Loading stored history. Live observation is paused."
      : `Browsing stored history, page ${history?.page || 1}. Live observation is paused.`;
    else if (output && phase === "following" && (!output.caughtUp || isTerminalJob(job))) {
      description = `Reading the latest stored output. Server result: ${job?.status || "unknown"}.`;
    }
    if (error) {
      const guidance = failureGuidance(error);
      description = `${guidance} ${retryAt === null ? historyMode ? "Read stopped. Reopen stored history or retry the page." : "Automatic observation stopped. Retry observation to read again." : "Retrying automatically with bounded backoff."}`;
    }
    writeText(elements.status, `${jobId}: ${description}`);
    writeText(elements.lastUpdated, `Last successful update: ${lastUpdatedAt === null ? "Not yet." : new Date(lastUpdatedAt).toISOString()}`);
    elements.pause.disabled = historyMode || !(phase === "loading" || phase === "following" || retryAt !== null);
    elements.resume.disabled = !historyMode && (phase === "loading" || phase === "following");
    elements.resume.textContent = historyMode ? "Resume live observation" : phase === "completed" ? "Refresh result" : phase === "error" ? "Retry observation" : "Resume observation";
    if (elements.history) {
      elements.history.disabled = !outputReaderFactory || !active() || !selection;
      elements.history.textContent = historyMode && error ? "Reopen stored history" : "Browse stored history";
    }
    if (elements.nextPage) {
      elements.nextPage.disabled = !historyMode || retryAt !== null || !history?.canNext || Boolean(error && !error.retryable);
      // Keep a busy next-page control focusable; its owned in-flight guard prevents duplicate reads.
      elements.nextPage.textContent = historyMode && phase === "history_loading" ? "Loading page..."
        : historyMode && error?.retryable && retryAt === null ? "Retry page" : "Next page";
    }
    if (elements.outputInfo && outputReaderFactory) writeText(elements.outputInfo,
      historyMode ? `Stored history · page ${history?.page || 1}. ${output?.caughtUp ? "Read through the current stored snapshot." : "Read the next page to continue."}`
        : output?.trimmed ? "The live view is limited. Some previously displayed output is outside this view; browse stored history to read earlier entries."
        : output && !output.caughtUp ? "More stored output remains. Reading in bounded pages."
        : "Live view of stored output. Browse stored history to read from the beginning.");
    if (focusedControl === elements.pause && elements.pause.disabled && !elements.resume.disabled) {
      elements.resume.focus({ preventScroll: true });
    } else if (focusedControl === elements.resume && elements.resume.disabled && !elements.pause.disabled) {
      elements.pause.focus({ preventScroll: true });
    }
    if (focusedControl === elements.nextPage && elements.nextPage?.disabled && !elements.resume.disabled) elements.resume.focus({ preventScroll: true });
    const text = outputReaderFactory
      ? output ? output.text || "No stored output is present in this snapshot."
        : phase === "loading" || phase === "history_loading" ? "Loading stored output from the Controller."
        : "No stored output snapshot loaded. The last server result is unchanged."
      : job
      ? chunks.length > 0 ? renderJobOutput(chunks, { jobId, job }) : renderJobOutputStatus(job, { jobId, observing: false })
      : `Job: ${jobId}\nNo server result loaded yet.`;
    const sameJob = renderedJobId === jobId;
    const top = sameJob ? elements.output.scrollTop : 0;
    const left = sameJob ? elements.output.scrollLeft : 0;
    writeText(elements.output, text);
    elements.output.scrollTop = top;
    elements.output.scrollLeft = left;
    renderedJobId = jobId;
    writeHtml(elements.targets, renderJobTargetTable(job));
    writeHtml(elements.artifacts, renderJobArtifacts(job));
    if (elements.provenance) writeText(elements.provenance, formatJobCatalogProvenance(job));
  }

  function ensureOwner() {
    if (owner) return owner;
    const created = createJobObserver({
      api: apiClient, isTerminal: isTerminalJob, clock,
      outputReader: outputReaderFactory?.(),
      onChange: (snapshot) => { if (owner === created && active()) render(snapshot); },
    });
    owner = created;
    return created;
  }

  function pause() {
    if (history) {
      cancelHistory();
      writeText(elements.status, "Stored history is paused. Resume observation to read the current result.");
      if (elements.nextPage) elements.nextPage.disabled = true;
      elements.pause.disabled = true; elements.resume.disabled = false;
    } else owner?.pause();
  }
  function resume() {
    cancelArtifactRead();
    if (active() && selection) {
      if (history || !owner) { cancelHistory(); ensureOwner().select(selection.jobId); }
      else ensureOwner().resume();
    }
  }

  /** @param {HistoryView} view @param {Readonly<import('./job-observer.js').ObservationSnapshot>} snapshot */
  function publishHistory(view, snapshot) {
    if (history !== view || !active() || selection !== view.selection) return false;
    view.snapshot = snapshot;
    try { render(snapshot); }
    catch {
      if (history === view) {
        view.canNext = false; view.reader.dispose();
        view.snapshot = Object.freeze({ ...snapshot, phase: "error", retryAt: null, error: Object.freeze({ kind: "view", status: null, retryable: false }) });
      }
      return false;
    }
    return history === view && active() && selection === view.selection;
  }

  /** One history page owns its Job/detail pair, deadline and finite retry timer. @param {HistoryView} view */
  async function loadHistoryPage(view) {
    if (history !== view || !active() || selection !== view.selection || historyRead) return;
    const prior = view.snapshot;
    const loading = Object.freeze({ phase: "history_loading", jobId: view.selection.jobId, job: prior?.job || null,
      chunks: [], output: prior?.output || null, lastUpdatedAt: prior?.lastUpdatedAt ?? null, retryAt: null, error: null, attempt: view.page });
    if (!publishHistory(view, loading)) return;
    const controller = new AbortController(), { signal } = controller;
    const deadline = clock.setTimeout(() => controller.abort(new DOMException("Stored history read timed out.", "TimeoutError")), 10000);
    const request = { controller, deadline, view };
    historyRead = request;
    let onAbort = () => {};
    /** @type {Promise<never>} */
    const canceled = new Promise((_, reject) => { onAbort = () => reject(signal.reason); signal.addEventListener("abort", onAbort, { once: true }); });
    const current = () => active() && selection === view.selection && history === view && historyRead === request;
    /** @type {number|null} */
    let retryDelay = null;
    try {
      const work = (async () => {
        const job = parseObservedJob(await apiClient.getJob(view.selection.jobId, { signal }), view.selection.jobId);
        signal.throwIfAborted();
        const output = await view.reader.readHistoryPage(view.selection.jobId, { signal });
        signal.throwIfAborted();
        return { job, output };
      })();
      const result = await Promise.race([work, canceled]);
      if (!current()) return;
      view.page += 1; view.failures = 0; view.canNext = result.output.hasMore || !result.output.caughtUp;
      renderedJobId = ""; // Explicit page navigation starts at the new page, unlike live background updates.
      publishHistory(view, Object.freeze({ phase: "history", jobId: view.selection.jobId, job: result.job,
        chunks: result.output.fragments, output: result.output, lastUpdatedAt: clock.now(), retryAt: null, error: null, attempt: view.page }));
    } catch (error) {
      if (!current()) return;
      const failure = classifyJobReadFailure(error, { outputPage: true });
      retryDelay = failure.retryable ? [1000, 2000, 4000][view.failures] ?? null : null;
      view.failures += 1;
      if (!publishHistory(view, Object.freeze({ ...loading, phase: "error", error: failure,
        retryAt: retryDelay === null ? null : clock.now() + retryDelay }))) retryDelay = null;
    } finally {
      clock.clearTimeout(deadline); signal.removeEventListener("abort", onAbort);
      if (historyRead === request) historyRead = null;
    }
    if (retryDelay !== null && history === view && active()) view.timer = clock.setTimeout(() => {
      view.timer = null; void loadHistoryPage(view);
    }, retryDelay);
  }

  async function browseHistory() {
    if (!active() || !selection || !outputReaderFactory) return;
    const selected = selection;
    release();
    const reader = outputReaderFactory(); reader.reset(selected.jobId);
    /** @type {HistoryView} */
    const view = { selection: selected, reader, page: 0, canNext: true, snapshot: null, failures: 0, timer: null };
    history = view;
    await loadHistoryPage(view);
  }

  async function nextHistoryPage() {
    const view = history;
    if (!view || !view.canNext || historyRead || view.timer !== null || (view.snapshot?.error && !view.snapshot.error.retryable)) return;
    view.failures = 0;
    await loadHistoryPage(view);
  }

  const onBrowseHistory = () => { void browseHistory(); };
  const onNextHistoryPage = () => { void nextHistoryPage(); };

  /** @param {string} jobId @param {string} artifactId */
  async function showArtifact(jobId, artifactId) {
    if (!active() || selection?.jobId !== jobId || !apiClient.getJobArtifact) return;
    pause();
    cancelArtifactRead();
    if (elements.outputInfo && outputReaderFactory) writeText(elements.outputInfo, "Artifact inspection. Stored output observation is paused.");
    const currentSelection = selection;
    const controller = new AbortController();
    const { signal } = controller;
    const deadline = clock.setTimeout(() => controller.abort(new DOMException("Artifact read timed out.", "TimeoutError")), 10000);
    const request = { controller, deadline };
    artifactRead = request;
    writeText(elements.output, `Loading artifact ${artifactId}. Job observation is paused.`);
    let onAbort = () => {};
    /** @type {Promise<never>} */
    const canceled = new Promise((_, reject) => {
      onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
    });
    const current = () => active() && selection === currentSelection && artifactRead === request;
    try {
      const artifact = await Promise.race([apiClient.getJobArtifact(jobId, artifactId, { signal }), canceled]);
      if (current()) writeText(elements.output, renderArtifactBody(artifact));
    } catch {
      if (current()) writeText(elements.output, signal.reason?.name === "TimeoutError"
        ? "Artifact read timed out. Resume job observation or retry the artifact."
        : "Could not load artifact. Check access and retry, or resume job observation.");
    } finally {
      clock.clearTimeout(deadline);
      signal.removeEventListener("abort", onAbort);
      if (artifactRead === request) artifactRead = null;
    }
  }
  elements.pause.addEventListener("click", pause);
  elements.resume.addEventListener("click", resume);
  elements.history?.addEventListener("click", onBrowseHistory);
  elements.nextPage?.addEventListener("click", onNextHistoryPage);
  renderIdle();

  return {
    /** @param {{ route: string, authenticated: boolean, authGeneration?:number }} context */
    setContext(context) {
      if (disposed || (context.route === route && context.authenticated === authenticated && (context.authGeneration ?? 0) === authGeneration)) return;
      const changedIdentity = (context.authGeneration ?? 0) !== authGeneration;
      release();
      authGeneration = context.authGeneration ?? 0;
      route = context.route;
      authenticated = context.authenticated;
      selection = authenticated && !changedIdentity && selection ? Object.freeze({ jobId: selection.jobId }) : null;
      if (!authenticated || !active() || !selection) renderIdle();
      else if (active() && selection) ensureOwner().select(selection.jobId);
    },
    /** @param {string} jobId */
    select(jobId) {
      if (disposed || !authenticated) return;
      const id = String(jobId).trim();
      if (!id) throw new Error("A Job ID is required.");
      cancelArtifactRead();
      cancelHistory();
      selection = Object.freeze({ jobId: id });
      if (active()) ensureOwner().select(id);
    },
    pause,
    resume,
    showArtifact,
    browseHistory,
    nextHistoryPage,
    getSnapshot: () => owner?.getSnapshot() || history?.snapshot || null,
    getJobId: () => selection?.jobId || "",
    captureSelection: () => selection,
    isCurrentSelection: (value) => active() && value !== null && value === selection,
    dispose() {
      disposed = true;
      selection = null;
      release();
      elements.pause.removeEventListener("click", pause);
      elements.resume.removeEventListener("click", resume);
      elements.history?.removeEventListener("click", onBrowseHistory);
      elements.nextPage?.removeEventListener("click", onNextHistoryPage);
    },
  };
}

function renderOverviewSummary({ agents, jobs, approvals, remediations }) {
  const summary = [
    ["Known agents", Array.isArray(agents) ? agents.length : 0],
    ["Recent jobs", Array.isArray(jobs) ? jobs.length : 0],
    ["Pending approvals", Array.isArray(approvals) ? approvals.length : 0],
    ["Remediation requests", Array.isArray(remediations) ? remediations.length : 0],
  ];
  return `<div class="overview-grid">${summary
    .map(
      ([label, value]) => `<div class="overview-card"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`,
    )
    .join("")}</div>`;
}

const METRICS_CHARTS = [
  {
    label: "CPU used",
    unit: "%",
    read: (body) => asNumber(body?.cpu?.usage_percent),
  },
  {
    label: "Memory used",
    unit: "%",
    read: (body) => memoryUsedPercent(body),
  },
  {
    label: "Disk used",
    unit: "%",
    read: (body) => diskUsedPercent(body),
  },
  {
    label: "Processes",
    unit: "",
    read: (body) => asNumber(body?.process?.count),
  },
  {
    label: "Failed units",
    unit: "",
    read: (body) => asNumber(body?.service?.failed_units_count),
  },
];

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderAgents(agents, selectedAgentId = "") {
  if (!Array.isArray(agents) || agents.length === 0) {
    return '<div class="empty">No agents enrolled.</div>';
  }
  return agents
    .map((agent) => {
      const labels = Array.isArray(agent.labels)
        ? agent.labels.map((label) => `${label.key}=${label.value}`).join(", ")
        : "";
      const platform = [agent.os, agent.arch].filter(Boolean).join("/");
      const age =
        typeof agent.last_seen_age_seconds === "number"
          ? `last seen ${agent.last_seen_age_seconds}s ago`
          : "";
      const session = agent.connected ? "session connected" : "session disconnected";
      const meta = [agent.hostname, platform, session, age].filter(Boolean).join(" · ");
      const selectedClass = agent.id === selectedAgentId ? " selected" : "";
      const status = agentDisplayStatus(agent);
      const revokedBadge = agent.revoked
        ? '<span class="status-pill revoked">revoked</span>'
        : "";
      return `
        <button class="agent-row${selectedClass}" type="button" data-agent-id="${escapeHtml(agent.id)}">
          <span>
            <strong>${escapeHtml(agent.name || agent.id)}</strong>
            <small>${escapeHtml(agent.id)}</small>
          </span>
          <span class="agent-status">
            <span class="status-pill ${escapeHtml(status)}">${escapeHtml(status)}</span>
            ${revokedBadge}
          </span>
          <small class="labels">${escapeHtml(labels || "no labels")}</small>
          <small class="agent-meta">${escapeHtml(meta || "no facts summary")}</small>
        </button>
      `;
    })
    .join("");
}

export function agentDisplayStatus(agent) {
  if (agent?.revoked) {
    return "offline";
  }
  if (agent?.connected) {
    return "online";
  }
  if (agent?.status === "reconnecting") {
    return "stale";
  }
  return agent?.status || "unknown";
}

export function renderAgentDetail(agent) {
  if (!agent) {
    return '<div class="empty">Select an agent.</div>';
  }
  const status = agentDisplayStatus(agent);
  const policies = Array.isArray(agent.assigned_policy_ids)
    ? agent.assigned_policy_ids.join(", ")
    : "";
  const capabilities = Array.isArray(agent.capabilities)
    ? agent.capabilities.join(", ")
    : "";
  const rows = [
    ["Status", status],
    ["Session", agent.connected ? "connected" : "disconnected"],
    ["Revoked", agent.revoked ? "yes" : "no"],
    ["Hostname", agent.hostname],
    ["Platform", [agent.os, agent.arch].filter(Boolean).join("/")],
    ["Last seen", typeof agent.last_seen_age_seconds === "number" ? `${agent.last_seen_age_seconds}s ago` : ""],
    ["Assigned policies", policies],
    ["Capabilities", capabilities],
    ["Capability reported", formatUnixMillis(agent.capability_reported_at_ms)],
  ];
  return `
    <div class="detail-grid">
      ${rows
        .map(
          ([label, value]) => `
            <div>
              <small>${escapeHtml(label)}</small>
              <strong>${escapeHtml(formatOptional(value))}</strong>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

export function renderSnapshot(snapshot, missingText) {
  if (!snapshot || !snapshot.body) {
    return missingText;
  }
  const agentTime = formatUnixMillis(snapshot.agent_system_time_ms);
  const collectedAt = formatUnixMillis(snapshot.collected_at_ms);
  const header = [
    agentTime ? `Agent time: ${agentTime}` : "",
    collectedAt ? `Stored at: ${collectedAt}` : "",
  ].filter(Boolean);
  const body = JSON.stringify(snapshot.body, null, 2);
  return header.length > 0 ? `${header.join("\n")}\n\n${body}` : body;
}

export function renderFactsInventory(snapshot, missingText = "No facts snapshot.") {
  if (!snapshot || !snapshot.body) {
    return `<div class="empty">${escapeHtml(missingText)}</div>`;
  }
  const body = snapshot.body;
  const rows = [
    ["OS", [body.os, body.arch].filter(Boolean).join("/")],
    ["Hostname", body.hostname],
    ["CPU logical cores", body?.cpu?.logical_count],
    ["Memory total", formatKilobytes(body?.memory?.total_kb)],
    [
      "Memory modules",
      body?.memory?.module_count_known === false
        ? "unknown"
        : formatOptional(body?.memory?.module_count),
    ],
    ["Disk devices", formatOptional(body?.disk?.device_count)],
    ["Mounts", formatOptional(body?.disk?.mount_count)],
    ["Root disk total", formatKilobytes(body?.disk?.root_total_kb)],
    ["Root filesystem", body?.disk?.root_filesystem],
    ["Root FS type", body?.disk?.root_fs_type],
    [
      "Network interfaces",
      Array.isArray(body?.network?.interfaces)
        ? String(body.network.interfaces.length)
        : "unknown",
    ],
  ];
  return `
    <div class="inventory-grid">
      ${rows
        .map(
          ([label, value]) => `
            <div class="inventory-card">
              <small>${escapeHtml(label)}</small>
              <strong>${escapeHtml(formatOptional(value))}</strong>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

export function renderDiskInventory(snapshot, missingText = "No disk inventory.") {
  if (!snapshot || !snapshot.body) {
    return `<div class="empty">${escapeHtml(missingText)}</div>`;
  }
  const disk = snapshot.body.disk || {};
  const devices = Array.isArray(disk.devices) ? disk.devices : [];
  const mounts = Array.isArray(disk.mounts) ? disk.mounts : [];
  const deviceRows = devices.flatMap((device) => {
    const base = [
      {
        name: device.name,
        kind: device.kind,
        size: formatKilobytes(device.size_kb),
        mount: "device",
        fs: "",
      },
    ];
    const partitions = Array.isArray(device.partitions)
      ? device.partitions.map((partition) => ({
          name: partition.name,
          kind: "partition",
          size: formatKilobytes(partition.size_kb),
          mount: "",
          fs: "",
        }))
      : [];
    return base.concat(partitions);
  });
  const mountRows = mounts.map((mount) => ({
    name: mount.source,
    kind: "mount",
    size: "",
    mount: mount.mount_point,
    fs: mount.fs_type,
  }));
  const rows = deviceRows.concat(mountRows);
  if (rows.length === 0) {
    return `<div class="empty">${escapeHtml(missingText)}</div>`;
  }
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Source</th>
          <th>Kind</th>
          <th>Size</th>
          <th>Mount</th>
          <th>FS</th>
        </tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (row) => `
              <tr>
                <td>${escapeHtml(formatOptional(row.name))}</td>
                <td>${escapeHtml(formatOptional(row.kind))}</td>
                <td>${escapeHtml(row.size || "")}</td>
                <td>${escapeHtml(row.mount || "")}</td>
                <td>${escapeHtml(row.fs || "")}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

export function renderDrift(report) {
  if (!report) {
    return '<div class="empty">No drift report.</div>';
  }
  const agentTime = formatUnixMillis(report.agent_system_time_ms);
  const checkedAt = formatUnixMillis(report.checked_at_ms);
  const timeMeta = [agentTime ? `Agent time ${agentTime}` : "", checkedAt ? `Checked ${checkedAt}` : ""]
    .filter(Boolean)
    .join(" | ");
  const remediation = [
    report.acknowledged ? `acknowledged by ${report.acknowledged_by || "operator"}` : "open",
    report.resolved ? `resolved by ${report.resolution_job_id || "remediation job"}` : "not resolved",
  ].join(" · ");
  return `
    <div class="drift-summary">
      <span class="status-pill ${escapeHtml(report.status)}">${escapeHtml(report.status)}</span>
      <strong>${escapeHtml(report.policy_name)}</strong>
    </div>
    ${timeMeta ? `<div class="snapshot-time">${escapeHtml(timeMeta)}</div>` : ""}
    <div class="snapshot-time">${escapeHtml(remediation)}</div>
    <div class="diff-grid">
      <section>
        <h3>Expected</h3>
        <pre>${escapeHtml(report.expected)}</pre>
      </section>
      <section>
        <h3>Actual</h3>
        <pre>${escapeHtml(report.actual)}</pre>
      </section>
    </div>
  `;
}

export function renderDriftHistory(page) {
      const reports = snapshotItems(page);
  if (reports.length === 0) {
    return '<div class="empty">No drift history.</div>';
  }
  return reports
    .map(
      (report) => `
        <div class="compact-row">
          <span class="status-pill ${escapeHtml(report.status || "unknown")}">${escapeHtml(report.status || "unknown")}</span>
          <span>
            <strong>${escapeHtml(report.policy_name || "policy")}</strong>
            <small>${escapeHtml(formatUnixMillis(report.agent_system_time_ms || report.checked_at_ms) || "unknown time")}</small>
            <small>${escapeHtml(report.resolved ? `resolved by ${report.resolution_job_id || "remediation job"}` : "open")}</small>
          </span>
        </div>
      `,
    )
    .join("");
}

export function formatUnixMillis(value) {
  if (!Number.isFinite(value)) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return `${date.toISOString()} (${value} ms)`;
}

export function asNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

export function percent(part, total) {
  const partNumber = asNumber(part);
  const totalNumber = asNumber(total);
  if (partNumber === null || totalNumber === null || totalNumber <= 0) {
    return null;
  }
  return (partNumber / totalNumber) * 100;
}

export function diskUsedPercent(body) {
  const direct = asNumber(body?.disk?.used_percent);
  if (direct !== null) {
    return direct;
  }
  const used = asNumber(body?.disk?.used_kb);
  const total = asNumber(body?.disk?.total_kb);
  if (used === null || total === null || total <= 0) {
    return null;
  }
  return (used / total) * 100;
}

export function memoryUsedPercent(body) {
  const direct = asNumber(body?.memory?.used_percent);
  if (direct !== null) {
    return direct;
  }
  return percent(body?.memory?.used_kb, body?.memory?.total_kb);
}

export function formatKilobytes(value) {
  const kilobytes = asNumber(value);
  if (kilobytes === null) {
    return "unknown";
  }
  if (kilobytes >= 1024 * 1024) {
    return `${(kilobytes / 1024 / 1024).toFixed(1)} GiB`;
  }
  if (kilobytes >= 1024) {
    return `${(kilobytes / 1024).toFixed(1)} MiB`;
  }
  return `${kilobytes} KiB`;
}

function formatOptional(value) {
  return value === null || value === undefined || value === "" ? "unknown" : String(value);
}

export function snapshotTimeMs(snapshot) {
  return (
    asNumber(snapshot?.agent_system_time_ms) ??
    asNumber(snapshot?.collected_at_ms) ??
    asNumber(snapshot?.checked_at_ms) ??
    asNumber(snapshot?.body?.system_time_ms)
  );
}

export function recentSnapshots(snapshots, windowMs = DEFAULT_TELEMETRY_WINDOW_MS) {
  const rows = (Array.isArray(snapshots) ? snapshots : [])
    .map((snapshot) => ({ snapshot, time: snapshotTimeMs(snapshot) }))
    .filter((row) => row.time !== null)
    .sort((left, right) => left.time - right.time);
  if (rows.length === 0) {
    return [];
  }
  const newest = rows[rows.length - 1].time;
  const cutoff = newest - windowMs;
  return rows.filter((row) => row.time >= cutoff).map((row) => row.snapshot);
}

export function renderTelemetryCharts(
  snapshots,
  definitions,
  emptyText = "No recent telemetry snapshots.",
  windowMs = DEFAULT_TELEMETRY_WINDOW_MS,
) {
  const recent = recentSnapshots(snapshots, windowMs);
  if (recent.length === 0) {
    return `<div class="empty">${escapeHtml(emptyText)}</div>`;
  }
  const first = snapshotTimeMs(recent[0]);
  const last = snapshotTimeMs(recent[recent.length - 1]);
  const range = [formatClock(first), formatClock(last)].filter(Boolean).join(" - ");
  const cards = definitions
    .map((definition) => renderChartCard(recent, definition))
    .join("");
  return `
    <div class="chart-window">
      <strong>Last ${escapeHtml(formatDuration(windowMs))}</strong>
      <small>${escapeHtml(range || `${recent.length} sample(s)`)}</small>
    </div>
    <div class="chart-grid">${cards}</div>
  `;
}

function formatDuration(value) {
  const milliseconds = asNumber(value);
  if (milliseconds === null || milliseconds <= 0) {
    return "5 minutes";
  }
  const minutes = Math.round(milliseconds / 60_000);
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}

function renderChartCard(snapshots, definition) {
  const series = snapshots
    .map((snapshot) => ({
      time: snapshotTimeMs(snapshot),
      value: definition.read(snapshot.body || {}),
    }))
    .filter((point) => point.time !== null && point.value !== null);
  const latest = series.length > 0 ? series[series.length - 1].value : null;
  const latestLabel = latest === null ? "No samples" : formatMetricValue(latest, definition.unit);
  return `
    <article class="chart-card">
      <div class="chart-card-heading">
        <span>${escapeHtml(definition.label)}</span>
        <strong>${escapeHtml(latestLabel)}</strong>
      </div>
      ${renderSparkline(series)}
    </article>
  `;
}

function renderSparkline(series) {
  if (series.length === 0) {
    return '<div class="chart-empty">No samples</div>';
  }
  const width = 300;
  const height = 96;
  const padX = 10;
  const padY = 14;
  const values = series.map((point) => point.value);
  let min = Math.min(...values);
  let max = Math.max(...values);
  if (min === max) {
    min -= 1;
    max += 1;
  }
  const points = series
    .map((point, index) => {
      const x =
        series.length === 1 ? width / 2 : padX + (index * (width - padX * 2)) / (series.length - 1);
      const ratio = (point.value - min) / (max - min);
      const y = height - padY - ratio * (height - padY * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return `
    <svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Telemetry trend">
      <line class="sparkline-axis" x1="${padX}" y1="${height - padY}" x2="${width - padX}" y2="${height - padY}"></line>
      <polyline class="sparkline-line" points="${points}"></polyline>
    </svg>
  `;
}

function formatMetricValue(value, unit) {
  if (unit === "%") {
    return `${value.toFixed(1)}%`;
  }
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatClock(value) {
  const number = asNumber(value);
  if (number === null) {
    return "";
  }
  const date = new Date(number);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString().slice(11, 19);
}

export function renderAudit(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return '<div class="empty">No audit events.</div>';
  }
  return events
    .map(
      (event) => `
        <div class="audit-row">
          <span class="status-pill ${escapeHtml(event.category)}">${escapeHtml(event.category)}</span>
          <strong>${escapeHtml(event.action)}</strong>
          <small>${escapeHtml(event.actor)} -> ${escapeHtml(event.target)}</small>
          <code>${escapeHtml(event.value_kind)}:${escapeHtml(event.value)}</code>
        </div>
      `,
    )
    .join("");
}

export function renderJobs(jobs) {
  if (!Array.isArray(jobs) || jobs.length === 0) {
    return '<div class="empty">No jobs created.</div>';
  }
  return jobs
    .map((job) => {
      const command = [job.command_program, ...(job.command_args || [])].filter(Boolean).join(" ");
      const dispatchState = job.dispatch_state || job.status || "unknown";
      const targets = Array.isArray(job.target_agents) ? job.target_agents : [];
      const connectedCount = targets.filter((target) => target?.connected).length;
      const targetSummary =
        targets.length > 0
          ? `${targets.length} target(s), ${connectedCount} connected`
          : `${job.target_count ?? 0} target(s)`;
      const assignmentSummarySource =
        job.assignment_summary && typeof job.assignment_summary === "object" ? job.assignment_summary : null;
      const assignmentEntries = assignmentSummarySource
        ? ["queued", "dispatched", "accepted", "started", "succeeded", "failed", "rejected", "canceled", "expired", "skipped"]
            .map((status) => [status, Number(assignmentSummarySource[status] || 0)])
            .filter(([, count]) => count > 0)
        : Array.from(
            targets.reduce((counts, target) => {
              const status = target?.assignment_status;
              if (status) {
                counts.set(status, (counts.get(status) || 0) + 1);
              }
              return counts;
            }, new Map()),
          );
      const assignmentSummary =
        assignmentEntries.length > 0
          ? `, ${assignmentEntries.map(([status, count]) => `${count} ${status}`).join(", ")}`
          : "";
      return `
        <button class="job-row" type="button" data-job-id="${escapeHtml(job.id)}">
          <span>
            <strong>${escapeHtml(job.id)}</strong>
            <small>${escapeHtml(command || "non-command job")}</small>
          </span>
          <span class="job-status">
            <span class="status-pill ${escapeHtml(job.status || "unknown")}">${escapeHtml(job.status || "unknown")}</span>
            <span class="status-pill ${escapeHtml(dispatchState)}">${escapeHtml(dispatchState)}</span>
          </span>
          <small>${escapeHtml(`${targetSummary}${assignmentSummary}`)}</small>
        </button>
      `;
    })
    .join("");
}

/** Formats only verified provenance fields for a textContent result view. */
export function formatJobCatalogProvenance(job) {
  if (!job || !("catalog_provenance" in job)) return "Catalog provenance was not reported by this Controller.";
  const value = job.catalog_provenance;
  if (value === null) return "No catalog provenance. This Job was created through another input path.";
  if (!value || typeof value !== "object" || typeof value.source_id !== "string" || !value.source_id
      || typeof value.path !== "string" || !value.path || typeof value.commit !== "string"
      || !/^[a-f0-9]{40}([a-f0-9]{24})?$/.test(value.commit) || typeof value.checksum !== "string" || !/^[a-f0-9]{64}$/.test(value.checksum)) return "Catalog provenance could not be verified.";
  return `Catalog source: ${value.source_id}\nCommit: ${value.commit}\nDocument: ${value.path}\nSHA256: ${value.checksum}`;
}

export function renderJobTargetTable(job) {
  const targets = Array.isArray(job?.target_agents) ? job.target_agents : [];
  if (targets.length === 0) {
    return '<div class="empty">No target assignment details.</div>';
  }
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Agent state</th>
          <th>Session</th>
          <th>Assignment</th>
          <th>Task</th>
          <th>Last error</th>
        </tr>
      </thead>
      <tbody>
        ${targets
          .map(
            (target) => `
              <tr>
                <td>${escapeHtml(target.agent_id || "agent")}</td>
                <td>${escapeHtml(target.revoked ? "revoked" : target.status || "unknown")}</td>
                <td>${escapeHtml(target.connected ? "connected" : "disconnected")}</td>
                <td>${escapeHtml(target.assignment_status || "not assigned")}</td>
                <td>${escapeHtml(target.task_id || "")}</td>
                <td>${escapeHtml(target.last_error || "")}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

export function renderJobArtifacts(job) {
  const artifacts = Array.isArray(job?.rendered_artifacts) ? job.rendered_artifacts : [];
  if (artifacts.length === 0) {
    return '<div class="empty">No rendered artifacts.</div>';
  }
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Artifact</th>
          <th>Class</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${artifacts
          .map((artifact) => {
            const checksum = String(artifact?.checksum_sha256 || "");
            return `
              <tr class="artifact-row">
                <td>
                  <strong>${escapeHtml(artifact?.artifact_id || "artifact")}</strong>
                  <small>${escapeHtml(`agent=${artifact?.agent_id || ""} task=${artifact?.task_id || ""}`)}</small>
                  <small>${escapeHtml(`sha256=${checksum.slice(0, 12)} size=${artifact?.size_bytes ?? 0}`)}</small>
                </td>
                <td>${escapeHtml(artifact?.retention_class || "artifact")}</td>
                <td>
                  <button type="button" data-artifact-id="${escapeHtml(artifact?.artifact_id || "")}" data-artifact-job-id="${escapeHtml(job?.id || "")}">Open</button>
                </td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

export function renderArtifactBody(artifact) {
  if (!artifact) {
    return "Artifact body is missing or no longer available.";
  }
  const bytes = Array.isArray(artifact.content_bytes)
    ? artifact.content_bytes.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value >= 0 && value <= 255)
    : [];
  const checksum = String(artifact.checksum_sha256 || "");
  const text = printableArtifactPreview(bytes);
  const lines = [
    `Artifact: ${artifact.artifact_id || ""}`,
    `Job: ${artifact.job_id || ""}`,
    `Agent: ${artifact.agent_id || ""}`,
    `Task: ${artifact.task_id || ""}`,
    `Class: ${artifact.retention_class || ""}`,
    `Size: ${artifact.size_bytes ?? bytes.length} bytes`,
    `SHA-256: ${checksum.slice(0, 12)}`,
    "",
    text ? `Preview:\n${text}` : "Preview unavailable for non-printable content.",
  ];
  return lines.join("\n");
}

function printableArtifactPreview(bytes) {
  if (bytes.length === 0) {
    return "";
  }
  const visible = bytes.every((value) => value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126));
  if (!visible) {
    return "";
  }
  return String.fromCharCode(...bytes).slice(0, 4096);
}

export function renderApprovals(approvals, jobs = []) {
  if (!Array.isArray(approvals) || approvals.length === 0) {
    return '<div class="empty">No pending approvals.</div>';
  }
  return approvals
    .map((approval) => {
      const expires = formatUnixMillis(approval.expires_at_ms) || "unknown expiry";
      const job = Array.isArray(jobs) ? jobs.find((item) => item.id === approval.job_id) : null;
      const targets = Array.isArray(job?.target_agents) ? job.target_agents : [];
      const targetText =
        targets.length > 0
          ? targets.map((target) => `${target.agent_id || "agent"}:${target.assignment_status || "pending"}`).join(", ")
          : `${job?.target_count ?? 0} target(s)`;
      return `
        <div class="approval-row">
          <span class="status-pill ${escapeHtml(approval.status || "pending")}">${escapeHtml(approval.status || "pending")}</span>
          <span>
            <strong>${escapeHtml(approval.job_id || approval.id)}</strong>
            <small>${escapeHtml(approval.reason || "approval required")}</small>
            <small>${escapeHtml(targetText)}</small>
            <small>expires ${escapeHtml(expires)}</small>
          </span>
          <button type="button" data-approve-approval-id="${escapeHtml(approval.id)}">Approve</button>
          <button type="button" data-reject-approval-id="${escapeHtml(approval.id)}">Reject</button>
        </div>
      `;
    })
    .join("");
}

export function renderRemediations(remediations, selectedRemediationId = "") {
  if (!Array.isArray(remediations) || remediations.length === 0) {
    return '<div class="empty">No remediation requests.</div>';
  }
  return remediations
    .map((remediation) => {
      const selectedClass = remediation.id === selectedRemediationId ? " selected" : "";
      const updated = formatUnixMillis(remediation.updated_at_ms) || "unknown time";
      const job = remediation.job_id ? `job ${remediation.job_id}` : "no job";
      const verification = remediation.verification_assignment_status
        ? `verification ${remediation.verification_assignment_status}`
        : "verification not scheduled";
      const evidence = remediation.verification_evidence_status
        ? `evidence ${remediation.verification_evidence_status}`
        : "no verification evidence";
      const legacy = remediation.legacy_state || remediation.lifecycle_source !== "persisted"
        ? remediation.legacy_state || "legacy read model"
        : "persisted lifecycle";
      return `
        <button class="compact-row${selectedClass}" type="button" data-remediation-id="${escapeHtml(remediation.id)}">
          <span class="status-pill ${escapeHtml(remediation.status || "unknown")}">${escapeHtml(remediation.status || "unknown")}</span>
          <span>
            <strong>${escapeHtml(remediation.policy_id || remediation.policy_name || "policy")}</strong>
            <small>${escapeHtml(remediation.agent_id || "agent")} · ${escapeHtml(job)} · ${escapeHtml(updated)}</small>
            <small>${escapeHtml(remediation.runbook_ref || "no runbook ref")}</small>
            <small>${escapeHtml(remediation.risk_summary || "approval required")}</small>
            <small>${escapeHtml(verification)} · ${escapeHtml(evidence)} · ${escapeHtml(legacy)}</small>
          </span>
        </button>
      `;
    })
    .join("");
}

export function renderPolicies(policies, selectedPolicyId = "") {
  if (!Array.isArray(policies) || policies.length === 0) {
    return '<div class="empty">No policies saved.</div>';
  }
  return policies
    .map((policy) => {
      const selectedClass = policy.id === selectedPolicyId ? " selected" : "";
      return `
        <button class="policy-row${selectedClass}" type="button" data-policy-id="${escapeHtml(policy.id)}">
          <span>
            <strong>${escapeHtml(policy.name || policy.id)}</strong>
            <small>${escapeHtml(policy.id)}</small>
          </span>
          <span class="status-pill active">v${escapeHtml(policy.version || 1)}</span>
        </button>
      `;
    })
    .join("");
}

export function renderAgentPolicies(assignments, selectedAgentId = "") {
  if (!selectedAgentId) {
    return '<div class="empty">Select an agent to view assigned policies.</div>';
  }
  if (!Array.isArray(assignments) || assignments.length === 0) {
    return '<div class="empty">No policies assigned to this agent.</div>';
  }
  return assignments
    .map(
      (assignment) => `
        <div class="compact-row">
          <span class="status-pill active">assigned</span>
          <span>
            <strong>${escapeHtml(assignment.policy_id || "policy")}</strong>
            <small>${escapeHtml(formatUnixMillis(assignment.assigned_at_ms) || selectedAgentId)}</small>
          </span>
        </div>
      `,
    )
    .join("");
}

export function renderAgentLogs(page) {
  const chunks = snapshotItems(page);
  if (chunks.length === 0) {
    return '<div class="empty">No agent logs.</div>';
  }
  return chunks
    .map(
      (chunk) => `
        <div class="log-row">
          <small>${escapeHtml(formatUnixMillis(chunk.collected_at_ms) || "unknown time")}</small>
          <code>${escapeHtml(chunk.line || "")}</code>
        </div>
      `,
    )
    .join("");
}

export function renderEnrollmentTokens(tokens) {
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return '<div class="empty">No enrollment tokens created.</div>';
  }
  return tokens
    .map((token) => {
      const revokedClass = token.revoked ? " revoked" : "";
      const expiresAt = token.expires_at_epoch
        ? new Date(token.expires_at_epoch * 1000).toLocaleString()
        : "unknown";
      const labels = token.default_labels || "no default labels";
      const remaining = token.remaining_uses ?? Math.max((token.max_uses ?? 0) - (token.used_count ?? 0), 0);
      return `
        <div class="token-row${revokedClass}">
          <span>
            <strong>${escapeHtml(token.id)}</strong>
            <small>${escapeHtml(labels)}</small>
          </span>
          <span class="status-pill ${token.revoked ? "revoked" : "active"}">${token.revoked ? "revoked" : "active"}</span>
          <small>${escapeHtml(remaining)} of ${escapeHtml(token.max_uses ?? 0)} use(s) left</small>
          <small>expires ${escapeHtml(expiresAt)}</small>
          <button type="button" data-revoke-token-id="${escapeHtml(token.id)}" ${token.revoked ? "disabled" : ""}>Revoke</button>
        </div>
      `;
    })
    .join("");
}

export function buildRunbookJobRequest({ agentId, selector = "", document, confirmed }) {
  const targetSelector = String(selector ?? "").trim();
  if (!agentId && !targetSelector) {
    throw new Error("Select an agent or enter a target selector before creating a runbook job.");
  }
  const runbookDocument = String(document ?? "").trim();
  if (!runbookDocument) {
    throw new Error("Paste a runbook document before creating a job.");
  }
  if (!confirmed) {
    throw new Error("Check Confirm runbook execution before creating the job.");
  }
  const jobId = `job-runbook-ui-${Date.now()}`;
  const request = {
    job_id: jobId,
    target_agent_ids: targetSelector ? [] : [agentId],
    runbook_document: runbookDocument,
    timeout_seconds: 180,
    confirmed_high_risk: true,
    confirmed_by: "web-admin",
    expires_in_seconds: 300,
    nonce_prefix: jobId,
  };
  if (targetSelector) {
    request.selector = targetSelector;
  }
  return request;
}

export function buildPolicySaveRequest({ source }) {
  const policySource = String(source ?? "").trim();
  if (!policySource) {
    throw new Error("Paste a policy document before saving.");
  }
  return { source: policySource };
}

export function buildPolicyAssignmentRequest({ policyId, agentId }) {
  if (!policyId) {
    throw new Error("Select a policy first.");
  }
  if (!agentId) {
    throw new Error("Select an agent first.");
  }
  return { agent_id: agentId };
}

export function buildPolicyScheduleRequest({ policyId, agentId, intervalSeconds }) {
  if (!policyId) {
    throw new Error("Select a policy first.");
  }
  if (!agentId) {
    throw new Error("Select an agent first.");
  }
  const interval_seconds = Number.parseInt(intervalSeconds, 10);
  if (!Number.isInteger(interval_seconds) || interval_seconds < 1) {
    throw new Error("Drift interval must be at least 1 second.");
  }
  return { agent_id: agentId, interval_seconds };
}

export function renderCreatedEnrollmentToken(result, controllerUrl = "", agentName = "") {
  if (!result || !result.token) {
    return "Create a token to show the one-time value here.";
  }
  const url = controllerUrl || "https://fleet.example.com";
  const name = agentName || "agent-01";
  return [
    "One-time token:",
    result.token,
    "",
    "Agent init command:",
    `fleet agent init --url ${url} --token ${result.token} --name ${name}`,
  ].join("\n");
}

export function buildEnrollmentTokenRequest({ labels, maxUses, expiresInSeconds }) {
  const max_uses = Number.parseInt(maxUses, 10);
  const expires_in_seconds = Number.parseInt(expiresInSeconds, 10);
  if (!Number.isInteger(max_uses) || max_uses < 1) {
    throw new Error("Max uses must be at least 1.");
  }
  if (!Number.isInteger(expires_in_seconds) || expires_in_seconds < 1) {
    throw new Error("Expiry must be at least 1 second.");
  }
  return {
    labels: String(labels ?? "").trim(),
    max_uses,
    expires_in_seconds,
  };
}

function parseIntegerControl(value, label, minimum) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < minimum) {
    throw new Error(`${label} must be at least ${minimum}.`);
  }
  return parsed;
}

function parseAgentIds(value) {
  return String(value ?? "")
    .split(/[,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function buildStagedTrustBundleRequest({
  previousPublicKeyPath = "",
  agentIds = "",
  batchSize,
  maxFailures,
  ackTimeoutSeconds,
}) {
  const request = {
    batch_size: parseIntegerControl(batchSize, "Batch size", 1),
    max_failures: parseIntegerControl(maxFailures, "Max failures", 0),
    ack_timeout_seconds: parseIntegerControl(ackTimeoutSeconds, "Ack timeout", 1),
  };
  const previous_public_key_path = String(previousPublicKeyPath ?? "").trim();
  if (previous_public_key_path) {
    request.previous_public_key_path = previous_public_key_path;
  }
  const parsedAgentIds = parseAgentIds(agentIds);
  if (parsedAgentIds.length > 0) {
    request.agent_ids = parsedAgentIds;
  }
  return request;
}

export function renderControllerSigningRotationStatus(status) {
  if (!status || typeof status !== "object") {
    return '<div class="empty">No signing status loaded.</div>';
  }
  const rows = [
    ["Controller", status.controller_id],
    ["Persisted", status.persisted_record_present ? "yes" : "no"],
    ["State", status.persisted_state],
    ["Readiness", status.readiness],
    ["Bootstrap guard", status.bootstrap_guard],
    ["Agent trust", status.agent_trust_rollout],
    ["Active signing", status.active_signing_fingerprint_prefix],
    ["Selected signing", status.selected_signing_fingerprint_prefix],
    ["Old fingerprint", status.old_fingerprint_prefix],
    ["New fingerprint", status.new_fingerprint_prefix],
    ["Requested", formatUnixMillis(status.requested_at_ms)],
    ["Validated", formatUnixMillis(status.validated_at_ms)],
    ["Activated", formatUnixMillis(status.activated_at_ms)],
    ["Old verifies until", formatUnixMillis(status.old_key_verifies_until_ms)],
    ["Retired", formatUnixMillis(status.retired_at_ms)],
    ["Failed", formatUnixMillis(status.failed_at_ms)],
  ];
  return `
    <div class="detail-grid">
      ${rows
        .map(
          ([label, value]) => `
            <div>
              <small>${escapeHtml(label)}</small>
              <strong>${escapeHtml(formatOptional(value))}</strong>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

export function renderStagedTrustBundleResult(result) {
  if (!result || typeof result !== "object") {
    return '<div class="empty">No staged rollout result.</div>';
  }
  const counts = [
    ["Targets", result.target_count ?? 0],
    ["Planned", result.planned_count ?? 0],
    ["Attempted", result.attempted_count ?? 0],
    ["Updated", result.updated_count ?? 0],
    ["Skipped", result.skipped_count ?? 0],
    ["Failed", result.failed_count ?? 0],
    ["Current", result.already_current_count ?? 0],
    ["Unavailable", result.unavailable_count ?? 0],
    ["Pending", result.pending_count ?? 0],
    ["Entries", result.entries_count ?? 0],
  ];
  const agentRows = Array.isArray(result.agent_results)
    ? result.agent_results
        .map(
          (agent) => `
            <tr>
              <td>${escapeHtml(agent.agent_id || "")}</td>
              <td>${escapeHtml(agent.status || "unknown")}</td>
            </tr>
          `,
        )
        .join("")
    : "";
  return `
    <div class="detail-grid signing-grid">
      <div><small>Controller</small><strong>${escapeHtml(formatOptional(result.controller_id))}</strong></div>
      <div><small>Persisted state</small><strong>${escapeHtml(formatOptional(result.persisted_state))}</strong></div>
      <div><small>Rollout state</small><strong>${escapeHtml(formatOptional(result.rollout_state))}</strong></div>
      <div><small>Current fingerprint</small><strong>${escapeHtml(formatOptional(result.current_fingerprint_prefix))}</strong></div>
      <div><small>Previous fingerprint</small><strong>${escapeHtml(formatOptional(result.previous_fingerprint_prefix))}</strong></div>
    </div>
    <div class="preview-counts">
      ${counts.map(([label, value]) => `<span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small></span>`).join("")}
    </div>
    ${
      agentRows
        ? `<table class="data-table"><thead><tr><th>Agent</th><th>Status</th></tr></thead><tbody>${agentRows}</tbody></table>`
        : '<div class="empty">No agent results returned.</div>'
    }
  `;
}

export function parseCommandArgs(value) {
  return String(value ?? "")
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function buildCommandJobRequest({ agentId, selector = "", program, args, confirmed }) {
  const targetSelector = String(selector ?? "").trim();
  if (!agentId && !targetSelector) {
    throw new Error("Select an agent or enter a target selector before running a command.");
  }
  if (!program || !String(program).trim()) {
    throw new Error("Enter a program to run, for example uptime.");
  }
  if (!confirmed) {
    throw new Error("Check Confirm high-risk execution before running the command.");
  }
  const jobId = `job-ui-${Date.now()}`;
  const request = {
    job_id: jobId,
    target_agent_ids: targetSelector ? [] : [agentId],
    program: String(program).trim(),
    args: Array.isArray(args) ? args : parseCommandArgs(args),
    timeout_seconds: 30,
    confirmed_high_risk: true,
    confirmed_by: "web-admin",
    expires_in_seconds: COMMAND_JOB_EXPIRES_IN_SECONDS,
    nonce_prefix: jobId,
  };
  if (targetSelector) {
    request.selector = targetSelector;
  }
  return request;
}

export function buildSelectorPreviewRequest({ selector }) {
  const targetSelector = String(selector ?? "").trim();
  if (!targetSelector) {
    throw new Error("Enter a target selector before previewing targets.");
  }
  return { selector: targetSelector };
}

export function renderSelectorPreview(preview) {
  if (!preview || typeof preview !== "object") {
    return '<div class="empty">No selector preview.</div>';
  }
  const counts = [
    ["Matched", preview.matched_count ?? 0],
    ["Selected", preview.selected_count ?? 0],
    ["Disabled", preview.disabled_count ?? 0],
    ["Offline", preview.offline_count ?? 0],
  ];
  const warnings = Array.isArray(preview.warnings) ? preview.warnings : [];
  const agents = Array.isArray(preview.agents) ? preview.agents : [];
  const rows = agents
    .map((agent) => {
      const selected = Boolean(agent.selected_for_dispatch);
      const labels = Array.isArray(agent.labels)
        ? agent.labels.map((label) => `${label.key}=${label.value}`).join(", ")
        : "";
      return `
        <tr>
          <td>${escapeHtml(agent.name || agent.agent_id || "")}</td>
          <td>${escapeHtml(agent.agent_id || "")}</td>
          <td>${escapeHtml(labels || "none")}</td>
          <td>${escapeHtml(agent.status || "unknown")}</td>
          <td><span class="status-pill ${selected ? "active" : "revoked"}">${selected ? "selected" : "excluded"}</span></td>
        </tr>
      `;
    })
    .join("");
  return `
    <div class="preview-counts">
      ${counts.map(([label, value]) => `<span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small></span>`).join("")}
    </div>
    ${warnings.map((warning) => `<div class="preview-warning">${escapeHtml(warning.message || warning.code || "preview warning")}</div>`).join("")}
    ${
      rows
        ? `<table class="data-table"><thead><tr><th>Name</th><th>Agent</th><th>Labels</th><th>Status</th><th>Dispatch</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<div class="empty">No matching agents.</div>'
    }
  `;
}

export function selectorPreviewSelectedCount(preview) {
  const selectedCount = Number(preview?.selected_count ?? 0);
  return Number.isFinite(selectedCount) && selectedCount > 0 ? selectedCount : 0;
}

export function renderJobOutput(chunks, { jobId = "", job = null } = {}) {
  if (!Array.isArray(chunks) || chunks.length === 0) {
    return renderJobOutputStatus(job || { id: jobId, status: "success", dispatch_state: "completed" }, {
      jobId,
    });
  }
  const lines = [];
  if (jobId) {
    lines.push(`Job: ${jobId}`);
  }
  if (job) {
    lines.push(`Status: ${job.status || "unknown"}`);
    lines.push(`Dispatch: ${job.dispatch_state || "unknown"}`);
  }
  lines.push(`Output chunks: ${chunks.length}`, "");
  for (const chunk of chunks) {
    const sequence = Number.isFinite(chunk?.sequence) ? ` #${chunk.sequence}` : "";
    const prefix = `[${chunk?.agent_id || "agent"} ${chunk?.stream || "stdout"}${sequence}]`;
    const data = String(chunk?.data ?? "");
    if (data.includes("\n")) {
      lines.push(prefix, data.replace(/\n$/, ""));
    } else {
      lines.push(`${prefix} ${data}`);
    }
  }
  return lines.join("\n");
}

export function renderJobOutputWaiting({ jobId = "", attempt = 0, maxAttempts = JOB_OUTPUT_POLL_ATTEMPTS } = {}) {
  return renderJobOutputStatus(
    { id: jobId, status: "queued", dispatch_state: "created", target_agents: [] },
    { jobId, attempt, maxAttempts },
  );
}

export function renderJobOutputStatus(
  job,
  { jobId = "", attempt = 0, maxAttempts = JOB_OUTPUT_POLL_ATTEMPTS, paused = false, observing = true } = {},
) {
  const resolvedJobId = job?.id || jobId;
  const lines = [];
  if (resolvedJobId) {
    lines.push(`Job: ${resolvedJobId}`);
  }
  const progress = attempt > 0 ? ` (${attempt}/${maxAttempts})` : "";
  lines.push(`Status: ${job?.status || "unknown"}`);
  lines.push(`Dispatch: ${job?.dispatch_state || "unknown"}`);
  lines.push(jobStatusMessage(job));
  const targetSummary = jobTargetSummary(job);
  if (targetSummary) {
    lines.push(`Targets: ${targetSummary}`);
  }
  const expiresAt = formatUnixMillis(job?.expires_at_ms);
  if (expiresAt) {
    lines.push(`Expires at: ${expiresAt}`);
  }
  if (observing && !paused && !isTerminalJob(job)) {
    if (isApprovalPendingJob(job)) {
      lines.push("Use the Approvals section in Run or Runbooks before output can appear.");
    } else {
      lines.push(`Polling job output${progress}.`);
    }
  }
  if (paused) {
    lines.push("Polling paused. Refresh or select the job again to continue.");
  }
  return lines.join("\n");
}

export function renderJobOutputEmpty({ jobId = "", maxAttempts = JOB_OUTPUT_POLL_ATTEMPTS } = {}) {
  return renderJobOutputStatus(
    { id: jobId, status: "success", dispatch_state: "completed", target_agents: [] },
    { jobId, maxAttempts },
  );
}

export function jobStatusMessage(job) {
  const status = String(job?.status || "").toLowerCase();
  const dispatchState = String(job?.dispatch_state || "").toLowerCase();
  const reason = job?.last_error ? ` Reason: ${job.last_error}` : "";
  if (status === "pending_approval") {
    return `Approval required before dispatch.${reason}`;
  }
  if (dispatchState === "created") {
    return "Job created. Checking dispatch state.";
  }
  if (dispatchState === "queued") {
    return `Queued until agent reconnects.${reason}`;
  }
  if (dispatchState === "delivered" || dispatchState === "running" || status === "running") {
    return `Running on agent. Waiting for output.${reason}`;
  }
  if (dispatchState === "completed" || status === "success") {
    return "Completed with no output.";
  }
  if (dispatchState === "partial_success" || status === "partial_success") {
    return "Completed with mixed results. Check each Agent's Assignment.";
  }
  if (dispatchState === "expired" || status === "expired") {
    return `Expired before delivery or completion.${reason} Create a new job after the agent reconnects.`;
  }
  if (dispatchState === "canceled" || status === "canceled") {
    return `Canceled before completion.${reason} Check audit entries before retrying.`;
  }
  if (dispatchState === "rejected") {
    return `Rejected by controller policy.${reason} Review confirmation, target state, or audit entries before retrying.`;
  }
  if (dispatchState === "failed" || status === "failed") {
    if (job?.last_error === "execution_outcome_unknown" || job?.last_error === "exit_code=-1,reason=execution_outcome_unknown") {
      return `Execution outcome unknown.${reason} Do not assume success or repeat the command without checking its effects.`;
    }
    return `Job failed.${reason} Review job output or audit entries before retrying.`;
  }
  return `Job state is ${dispatchState || status || "unknown"}. Refresh jobs or check controller logs.`;
}

export function isTerminalJob(job) {
  const status = String(job?.status || "").toLowerCase();
  const dispatchState = String(job?.dispatch_state || "").toLowerCase();
  return TERMINAL_JOB_STATUSES.has(status) || TERMINAL_DISPATCH_STATES.has(dispatchState);
}

export function isApprovalPendingJob(job) {
  const status = String(job?.status || "").toLowerCase();
  const dispatchState = String(job?.dispatch_state || "").toLowerCase();
  return status === "pending_approval" || dispatchState === "pending_approval";
}

export function approvalDecisionJobToPoll(action, decision) {
  if (action !== "approve") {
    return "";
  }
  return String(decision?.job_id || "").trim();
}

function jobTargetSummary(job) {
  const targets = Array.isArray(job?.target_agents) ? job.target_agents : [];
  if (targets.length === 0) {
    return "";
  }
  return targets
    .map((target) => {
      const connected = target?.connected ? "connected" : "disconnected";
      const revoked = target?.revoked ? ", revoked" : "";
      return `${target?.agent_id || "agent"} ${target?.status || "unknown"} ${connected}${revoked}`;
    })
    .join("; ");
}

export function formatApiError(path, status) {
  if (status === 401) {
    return "Your login expired or was revoked. Sign in again.";
  }
  if (status === 403) {
    return "Your account does not have permission for this action.";
  }
  if (status === 404) {
    return `${path} was not found. Refresh the list and select an existing resource.`;
  }
  if (status === 409) {
    return `${path} conflicted with existing controller state. Refresh before retrying.`;
  }
  return `${path} returned ${status}`;
}

function setStatus(message, kind = "") {
  const element = document.querySelector("#status");
  element.textContent = message;
  element.className = `status ${kind}`.trim();
}

async function loadAuditPage({ append = false } = {}) {
  syncAdminTokenFromInput({ requireToken: true });
  const category = document.querySelector("#audit-category")?.value || "";
  const page = await api.exportAudit({ category, limit: 50, before: append ? state.auditCursor : "" });
  const items = Array.isArray(page?.items) ? page.items : [];
  state.auditItems = append ? [...state.auditItems, ...items] : items;
  state.auditCursor = String(page?.next_cursor || "");
  document.querySelector("#audit-list").innerHTML = renderAudit(state.auditItems);
  const more = document.querySelector("#load-more-audit");
  if (more) more.disabled = !state.auditCursor;
}

function showUiError(error) {
  if (error?.name !== "AbortError") setStatus(error.message, "error");
}

function readAdminTokenInput() {
  return normalizeAdminToken(document.querySelector("#admin-token")?.value || "");
}

/**
 * Owns one direct command/Runbook submission and a metadata-only uncertain ID.
 * It never retains or replays the command body, and never changes a server Job.
 */
export function createDirectJobSubmission({ createJob, getJob, onChange = () => {}, clock = globalThis }) {
  let authenticated = false, generation = 0, owner = {}, pending = null, disposed = false;
  let phase = "idle", jobId = "";
  const snapshot = () => Object.freeze({ phase, jobId,
    canSubmit: authenticated && !disposed && !pending && !["unknown", "submitting", "checking"].includes(phase),
    canCheck: authenticated && !disposed && !pending && Boolean(jobId) && ["unknown", "created", "missing"].includes(phase) });
  const current = token => !disposed && authenticated && owner === token;
  function publish() {
    try { onChange(snapshot()); return !disposed; }
    catch { disposed = true; pending?.abort(); return false; }
  }
  async function request(effect, token) {
    if (!current(token)) throw new DOMException("Authentication changed.", "AbortError");
    const controller = new AbortController();
    pending = controller;
    const deadline = clock.setTimeout(() => controller.abort(new DOMException("Submission timed out.", "TimeoutError")), 10000);
    let abort;
    const canceled = new Promise((_, reject) => {
      abort = () => reject(controller.signal.reason);
      controller.signal.addEventListener("abort", abort, { once: true });
    });
    try {
      return await Promise.race([Promise.resolve().then(() => {
        controller.signal.throwIfAborted(); return effect(controller.signal);
      }), canceled]);
    } finally {
      clock.clearTimeout(deadline); controller.signal.removeEventListener("abort", abort);
      if (pending === controller) pending = null;
    }
  }
  return {
    getSnapshot: snapshot,
    setContext(next) {
      if (disposed || (authenticated === next.authenticated && generation === (next.authGeneration ?? 0))) return;
      owner = {}; pending?.abort(new DOMException("Authentication changed.", "AbortError")); pending = null;
      if (phase === "submitting" || phase === "checking") phase = "unknown";
      authenticated = next.authenticated; generation = next.authGeneration ?? 0; publish();
    },
    async submit(body) {
      if (!snapshot().canSubmit) return null;
      if (typeof body?.job_id !== "string" || !body.job_id) throw new Error("A Job ID is required.");
      const token = owner;
      jobId = body.job_id; phase = "submitting";
      if (!publish() || !current(token)) return null;
      try {
        const response = await request(signal => createJob(body, { signal }), token);
        if (!current(token)) return null;
        if (response?.job_id !== jobId || typeof response.status !== "string") throw new Error("Invalid submission response.");
        phase = "created"; return publish() && current(token) ? response : null;
      } catch (error) {
        if (current(token)) {
          phase = [400, 401, 403, 404, 422].includes(error?.status) ? "rejected" : "unknown";
          publish();
        }
        return null;
      }
    },
    async check() {
      if (!snapshot().canCheck) return null;
      const token = owner, id = jobId;
      phase = "checking"; if (!publish() || !current(token)) return null;
      try {
        const job = await request(signal => getJob(id, { signal }), token);
        if (!current(token)) return null;
        if (job?.id !== id || typeof job.status !== "string") throw new Error("Invalid Job response.");
        phase = "created"; return publish() && current(token) ? job : null;
      } catch (error) {
        if (current(token)) { phase = error?.status === 404 ? "missing" : "unknown"; publish(); }
        return null;
      }
    },
    dispose() { if (disposed) return; disposed = true; owner = {}; pending?.abort(); pending = null; },
  };
}

function renderDirectSubmission(kind, view) {
  if (typeof document === "undefined") return;
  const messages = {
    idle: "No submission yet.", submitting: "Submitting Job ", checking: "Checking stored Job ",
    unknown: "Outcome unknown. Check stored Job before submitting again: ",
    created: "Stored Job: ", missing: "No stored Job found. A new submission requires your action: ",
    rejected: "Submission rejected: ",
  };
  const status = document.querySelector("#" + kind + "-submission-status");
  if (status) status.textContent = messages[view.phase] + view.jobId;
  const check = document.querySelector("#" + kind + "-check-submission");
  if (check) { check.hidden = !view.jobId; check.disabled = !view.canCheck; }
}


let lastAccountGeneration = -1;
let selectedAccountId = "";
let accountRows = "", tokenRows = "";
let onceReturnFocus = null;
let settingsSection = "account";

function clearOnceSecret(restoreFocus = false) {
  if (typeof document === "undefined") return;
  const input = document.querySelector("#once-secret");
  if (input) { input.value = ""; input.type = "password"; }
  const panel = document.querySelector("#once-secret-panel");
  if (panel) panel.hidden = true;
  document.querySelector("#reveal-once-secret")?.setAttribute("aria-pressed", "false");
  const reveal = document.querySelector("#reveal-once-secret");
  if (reveal) reveal.textContent = "Show value";
  const target = onceReturnFocus;
  onceReturnFocus = null;
  if (restoreFocus) {
    if (target?.isConnected && !target.disabled && target.getClientRects().length) target.focus({preventScroll:true});
    else document.querySelector("#login-username")?.focus({preventScroll:true});
  }
}
function showOnceSecret(value) {
  const target = onceReturnFocus || document.activeElement;
  clearOnceSecret();
  onceReturnFocus = target;
  const input = document.querySelector("#once-secret");
  input.value = value.value;
  document.querySelector("#once-secret-title").textContent = value.kind + " — shown once";
  document.querySelector("#once-secret-help").textContent = "Expires " + new Date(value.expiresAt * 1000).toLocaleString()
    + ". Copy it now and deliver setup/reset codes privately. Fleet cannot show it again.";
  document.querySelector("#once-secret-feedback").textContent = "";
  document.querySelector("#once-secret-panel").hidden = false;
  input.focus({ preventScroll: true });
}
function clearProtectedAccountView() {
  state.token = ""; state.agents = []; state.policies = []; state.remediations = [];
  state.selectedAgentId = ""; state.selectedPolicyId = ""; state.selectedRemediationId = "";
  state.auditCursor = ""; state.auditItems = []; state.createdEnrollmentToken = null;
  selectedAccountId = ""; accountRows = ""; tokenRows = "";
  settingsSection = "account";
  for (const id of ["admin-token", "login-password", "setup-code", "setup-password"]) {
    const field = document.querySelector("#" + id); if (field) field.value = "";
  }
  for (const id of ["agents-list", "agent-detail", "jobs-list", "approvals-list", "policies-list", "remediations-list", "audit-list", "enrollment-tokens-list", "admin-users-list", "personal-tokens-list"]) {
    const element = document.querySelector("#" + id); if (element) element.textContent = "Authenticate to load current data.";
  }
  for (const form of document.querySelectorAll(".account-form")) {
    for (const input of form.querySelectorAll('input[type="password"]')) input.value = "";
  }
  for (const id of ["run-command-form", "runbook-form", "remediation-form"]) document.querySelector("#" + id)?.reset();
}
function onAccountState(view) {
  if (typeof document === "undefined") return;
  if (lastAccountGeneration !== api.getAuthGeneration()) {
    lastAccountGeneration = api.getAuthGeneration(); clearProtectedAccountView();
  }
  const active = Boolean(view.user);
  const legacy = view.mode === "legacy";
  document.querySelector("#admin-auth").hidden = !legacy;
  document.querySelector("#personal-account-header").hidden = !active;
  document.querySelector("#personal-login").hidden = view.mode !== "personal" || active;
  document.querySelector("#local-owner-required").hidden = view.mode !== "local_setup_required";
  document.querySelector("#admin-workspace").hidden = !active && !legacy;
  document.querySelector(".page-heading").hidden = !active && !legacy;
  const error = document.querySelector("#account-error");
  error.hidden = !view.error; error.textContent = view.error?.message || "";
  const current = document.querySelector("#current-admin-user");
  document.querySelector("#logout-admin").disabled = view.phase === "signing_out";
  current.textContent = active ? (view.user.display_name || view.user.username) + " · " + view.user.role : "";
  document.querySelector("#account-profile").textContent = active ? view.user.username + " · " + view.user.id
    + " · login expires " + new Date(view.expiresAt * 1000).toLocaleString() : "";
  const route = currentAdminRoute();
  if (!active) settingsSection = "controller";
  if (settingsSection === "people" && view.user?.role !== "owner") settingsSection = "account";
  document.querySelector("#account-settings-tabs").hidden = route !== "settings" || (!active && !legacy);
  document.querySelector("#settings-account-tab").hidden = !active;
  document.querySelector("#settings-people-tab").hidden = view.user?.role !== "owner";
  for (const button of document.querySelectorAll("[data-settings-tab]")) {
    const selected = button.dataset.settingsTab === settingsSection;
    button.setAttribute("aria-selected", String(selected)); button.tabIndex = selected ? 0 : -1;
  }
  document.querySelector("#personal-account-panel").hidden = !active || route !== "settings" || settingsSection !== "account";
  document.querySelector("#owner-accounts-panel").hidden = view.user?.role !== "owner" || route !== "settings" || settingsSection !== "people";
  document.querySelector("#controller-settings-panel").hidden = route !== "settings" || settingsSection !== "controller";
  const managesController = active ? ["owner", "admin"].includes(view.user.role) : legacy;
  document.querySelector(".token-panel").hidden = route !== "settings" || !managesController;
  document.querySelector("#controller-access-note").hidden = managesController;
  for (const control of document.querySelectorAll("#staged-trust-bundle-form input, #staged-trust-bundle-form textarea, #staged-trust-bundle-form button")) control.disabled = !managesController;
  const executesJobs = active ? view.user.role !== "viewer" : legacy;
  document.querySelector("#job-permission-note").hidden = executesJobs || !["run", "runbooks", "remediations"].includes(route);
  for (const control of document.querySelectorAll("#run-command-form input, #run-command-form button, #runbook-form input, #runbook-form textarea, #runbook-form button, #remediation-form input, #remediation-form textarea, #remediation-form button, #expire-approvals")) control.disabled = !executesJobs;
  document.querySelector("#edit-admin-user-form").hidden = !selectedAccountId;
  const rows = view.users.map(user => '<button type="button" class="account-row account-secondary" data-user-id="' + escapeHtml(user.id) + '"><span><strong>'
    + escapeHtml(user.display_name || user.username) + '</strong><small>' + escapeHtml(user.username) + '</small></span><span>'
    + escapeHtml(user.role) + ' · ' + escapeHtml(user.status) + '</span></button>').join("") || '<p class="muted">No accounts on this page.</p>';
  if (rows !== accountRows) { accountRows = rows; document.querySelector("#admin-users-list").innerHTML = rows; }
  const tokens = view.tokens.map(token => '<div class="account-row"><span><strong>' + escapeHtml(token.label || "Unlabeled token") + '</strong><small>'
    + escapeHtml(token.id) + ' · expires ' + escapeHtml(new Date(token.expires_at * 1000).toLocaleString()) + '</small></span><span>'
    + (token.active ? 'Active <button type="button" class="account-secondary" data-personal-token-id="' + escapeHtml(token.id) + '">Revoke token</button>' : "Inactive") + '</span></div>').join("") || '<p class="muted">No personal tokens on this page. Create one to connect the CLI.</p>';
  if (tokens !== tokenRows) { tokenRows = tokens; document.querySelector("#personal-tokens-list").innerHTML = tokens; }
  document.querySelector("#next-admin-users").disabled = view.busy || !view.userCursor;
  document.querySelector("#next-personal-tokens").disabled = view.busy || !view.tokenCursor;
  for (const button of document.querySelectorAll("#personal-login button[type=submit], #personal-account-panel button, #owner-accounts-panel button")) {
    if (!["next-admin-users", "next-personal-tokens"].includes(button.id)) button.disabled = view.busy;
  }
  setStatus(view.error?.message || view.message, view.error ? "error" : "");
  for (const submission of Object.values(directSubmissions)) submission.setContext(adminViewContext());
  jobObservation?.setContext(adminViewContext()); void catalogPanel?.setContext(adminViewContext());
}
async function refreshAccountMetadata() {
  if (adminAccounts.getSnapshot().user?.role === "owner") await adminAccounts.loadUsers();
  if (adminAccounts.getSnapshot().user) await adminAccounts.loadTokens();
}
async function restoreAdminSession() {
  await adminAccounts.start();
  if (adminAccounts.getSnapshot().user) {
    await refreshAll().catch(showUiError);
    if (currentAdminRoute() === "settings") await refreshAccountMetadata();
  }
}
function wireAccountForms() {
  const activateTab = button => {
    if (!button || button.hidden) return;
    settingsSection = button.dataset.settingsTab;
    onAccountState(adminAccounts.getSnapshot());
    button.focus({preventScroll:true});
  };
  document.querySelector("#account-settings-tabs").addEventListener("click", event => activateTab(event.target.closest("[data-settings-tab]")));
  document.querySelector("#account-settings-tabs").addEventListener("keydown", event => {
    const buttons = [...document.querySelectorAll("[data-settings-tab]")].filter(button => !button.hidden);
    const index = buttons.indexOf(event.target); if (index < 0) return;
    const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1
      : event.key === "ArrowRight" ? (index + 1) % buttons.length : event.key === "ArrowLeft" ? (index + buttons.length - 1) % buttons.length : -1;
    if (next >= 0) { event.preventDefault(); activateTab(buttons[next]); }
  });
  const bind = (id, effect) => {
    const form = document.querySelector("#" + id);
    form.addEventListener("submit", event => {
      event.preventDefault();
      form.removeAttribute("aria-describedby");
      for (const input of form.querySelectorAll("input, select")) input.removeAttribute("aria-invalid");
      if (["personal-token-form", "create-admin-user-form"].includes(id)) onceReturnFocus = event.submitter;
      const body = Object.fromEntries(new FormData(form));
      for (const input of form.querySelectorAll('input[type="password"]')) input.value = "";
      const action = effect(body), generation = api.getAuthGeneration();
      void Promise.resolve(action).then(() => {
        if (generation !== api.getAuthGeneration()) return;
        if (["invalid", "authentication"].includes(adminAccounts.getSnapshot().error?.kind)) {
          form.setAttribute("aria-describedby", "account-error");
          for (const input of form.querySelectorAll("input, select")) input.setAttribute("aria-invalid", "true");
        }
      }).catch(showUiError);
    });
    form.addEventListener("input", event => { event.target.removeAttribute?.("aria-invalid"); });
  };
  bind("personal-login-form", async body => {
    if (await adminAccounts.login(body.username, body.password)) {
      await refreshAll().catch(showUiError);
      if (currentAdminRoute() === "settings") await refreshAccountMetadata();
    }
  });
  bind("password-setup-form", async body => {
    if (await adminAccounts.completeSetup(body.code, body.new_password)) {
      document.querySelector("#password-setup-form").hidden = true;
      document.querySelector("#personal-login-form").hidden = false;
      document.querySelector("#login-username").focus();
    }
  });
  bind("own-password-form", body => adminAccounts.changePassword(body));
  bind("personal-token-form", async body => {
    if (!body.label) delete body.label;
    if (await adminAccounts.createToken(body)) await adminAccounts.loadTokens();
  });
  bind("create-admin-user-form", async body => { if (await adminAccounts.createUser(body)) await adminAccounts.loadUsers(); });
  bind("edit-admin-user-form", async body => {
    if (selectedAccountId && await adminAccounts.changeUser(selectedAccountId, body) && adminAccounts.getSnapshot().user) await adminAccounts.loadUsers();
  });
  document.querySelector("#logout-admin").addEventListener("click", () => { void adminAccounts.logout(); });
  document.querySelector("#refresh-controller").addEventListener("click", () => { void refreshAll().catch(showUiError); });
  document.querySelector("#open-password-setup").addEventListener("click", () => {
    document.querySelector("#personal-login-form").hidden = true;
    document.querySelector("#password-setup-form").hidden = false; document.querySelector("#setup-code").focus();
  });
  document.querySelector("#close-password-setup").addEventListener("click", () => {
    document.querySelector("#password-setup-form").hidden = true; document.querySelector("#personal-login-form").hidden = false;
    document.querySelector("#setup-code").value = ""; document.querySelector("#setup-password").value = "";
    document.querySelector("#login-username").focus();
  });
  document.querySelector("#dismiss-once-secret").addEventListener("click", () => clearOnceSecret(true));
  document.querySelector("#once-secret-panel").addEventListener("keydown", event => {
    if (event.key === "Escape") { event.preventDefault(); clearOnceSecret(true); }
  });
  document.querySelector("#reveal-once-secret").addEventListener("click", () => {
    const input = document.querySelector("#once-secret"), reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    document.querySelector("#reveal-once-secret").setAttribute("aria-pressed", String(reveal));
    document.querySelector("#reveal-once-secret").textContent = reveal ? "Hide value" : "Show value";
  });
  document.querySelector("#copy-once-secret").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(document.querySelector("#once-secret").value); document.querySelector("#once-secret-feedback").textContent = "Copied. Store it safely, then clear this value."; }
    catch { document.querySelector("#once-secret-feedback").textContent = "Copy was unavailable. Show the value and copy it manually."; }
  });
  for (const [id,effect] of Object.entries({
    "refresh-admin-users":()=>adminAccounts.loadUsers(), "first-admin-users":()=>adminAccounts.loadUsers(),
    "next-admin-users":()=>adminAccounts.loadUsers({after:adminAccounts.getSnapshot().userCursor}),
    "refresh-personal-tokens":()=>adminAccounts.loadTokens(), "first-personal-tokens":()=>adminAccounts.loadTokens(),
    "next-personal-tokens":()=>adminAccounts.loadTokens({after:adminAccounts.getSnapshot().tokenCursor}),
  })) document.querySelector("#"+id).addEventListener("click",()=>{void effect();});
  document.querySelector("#admin-users-list").addEventListener("click",event=>{
    const button=event.target.closest("[data-user-id]");
    const user=adminAccounts.getSnapshot().users.find(value=>value.id===button?.dataset.userId);if(!user)return;
    selectedAccountId=user.id;
    document.querySelector("#edit-admin-user-form").hidden=false;
    document.querySelector("#selected-admin-user").textContent=user.username+" · "+user.id+" · "+user.status;
    document.querySelector("#edit-admin-name").value=user.display_name;
    document.querySelector("#edit-admin-role").value=user.role;
    document.querySelector("#edit-admin-password").value="";
    document.querySelector("#edit-admin-name").focus({preventScroll:true});
  });
  for(const [id,method] of [["reset-admin-password","resetUser"],["disable-admin-user","changeUser"]]) {
    document.querySelector("#"+id).addEventListener("click",async()=>{
      if (method === "resetUser") onceReturnFocus = document.querySelector("#"+id);
      const password=document.querySelector("#edit-admin-password");
      if(!password.reportValidity()||!selectedAccountId)return;
      const value=password.value;password.value="";
      if(!globalThis.confirm((method==="resetUser"?"Reset the password for ":"Disable ")+selectedAccountId+"? Existing logins and personal tokens will be revoked. Running Agent jobs continue."))return;
      const input=method==="resetUser"?{current_password:value}:{current_password:value,disable:true};
      if(await adminAccounts[method](selectedAccountId,input)&&adminAccounts.getSnapshot().user)await adminAccounts.loadUsers();
    });
  }
  document.querySelector("#personal-tokens-list").addEventListener("click",async event=>{
    const button=event.target.closest("[data-personal-token-id]");if(!button)return;
    if(!globalThis.confirm("Revoke this personal token? CLI/API requests using it will stop. Running Agent jobs continue."))return;
    if(await adminAccounts.revokeToken(button.dataset.personalTokenId))await adminAccounts.loadTokens();
  });
}

function adminViewContext(route = currentAdminRoute()) {
  return { route, authenticated: Boolean(state.token || adminAccounts.getSnapshot().user), authGeneration: api.getAuthGeneration() };
}

function setAdminToken(token) {
  if (state.token !== token) {
    state.token = token;
    api.setAuthentication({ mode: token ? "legacy" : "anonymous" });
  }
  for (const submission of Object.values(directSubmissions)) submission.setContext(adminViewContext());
  jobObservation?.setContext(adminViewContext());
  void catalogPanel?.setContext(adminViewContext());
}

function syncAdminTokenFromInput({ requireToken = false } = {}) {
  if (adminAccounts.getSnapshot().user) return "";
  const token = readAdminTokenInput();
  if (token) {
    setAdminToken(token);
  }
  if (requireToken && !state.token && !adminAccounts.getSnapshot().user) {
    throw new Error("Admin token is required. Paste the token from controller init, then retry.");
  }
  return state.token;
}

async function loadAgents() {
  const agents = await api.listAgents();
  state.agents = Array.isArray(agents) ? agents : [];
  const selected = state.agents.some((agent) => agent.id === state.selectedAgentId)
    ? state.selectedAgentId
    : state.agents[0]?.id || "";
  state.selectedAgentId = selected;
  document.querySelector("#agent-count").textContent = `${state.agents.length} known`;
  document.querySelector("#agents-list").innerHTML = renderAgents(state.agents, selected);
  syncAgentActions();
  if (selected) {
    await refreshSelectedAgent();
  }
}

async function loadSigningRotationStatus() {
  const status = await api.getControllerSigningRotationStatus();
  const element = document.querySelector("#signing-rotation-status");
  if (element) {
    element.innerHTML = renderControllerSigningRotationStatus(status);
  }
  return status;
}

function handleAgentsListClick(event) {
  const button = event.target?.closest?.("[data-agent-id]");
  if (!button?.dataset?.agentId) {
    return;
  }
  state.selectedAgentId = button.dataset.agentId;
  document.querySelector("#agents-list").innerHTML = renderAgents(state.agents, state.selectedAgentId);
  syncAgentActions();
  refreshSelectedAgent().catch(showUiError);
}

function selectedAgent() {
  return state.agents.find((agent) => agent.id === state.selectedAgentId) || null;
}

function syncAgentActions() {
  const revokeButton = document.querySelector("#revoke-agent-key");
  const refreshButton = document.querySelector("#refresh-telemetry");
  const assignButton = document.querySelector("#assign-policy");
  const scheduleButton = document.querySelector("#schedule-policy");
  const agent = selectedAgent();
  if (revokeButton) {
    revokeButton.disabled = !agent || Boolean(agent.revoked);
  }
  if (refreshButton) {
    refreshButton.disabled = !agent;
  }
  if (assignButton) {
    assignButton.disabled = !agent || !state.selectedPolicyId;
  }
  if (scheduleButton) {
    scheduleButton.disabled = !agent || !state.selectedPolicyId;
  }
  const detail = document.querySelector("#agent-detail");
  if (detail) {
    detail.innerHTML = renderAgentDetail(agent);
  }
}

async function refreshSelectedAgent() {
  const agentId = state.selectedAgentId;
  if (!agentId) {
    return;
  }
  const [facts, metrics, drift, metricsHistory, driftHistory, logs, agentPolicies] = await Promise.all([
    readOptionalAgentData("facts", () => api.getLatestFacts(agentId)),
    readOptionalAgentData("metrics", () => api.getLatestMetrics(agentId)),
    readOptionalAgentData("drift", () => api.getLatestDrift(agentId)),
    readOptionalAgentData("metrics history", () => api.listMetrics(agentId, { limit: TELEMETRY_PAGE_LIMIT })),
    readOptionalAgentData("drift history", () => api.listDrift(agentId, { limit: DETAIL_PAGE_LIMIT })),
    readOptionalAgentData("agent logs", () => api.listAgentLogs(agentId, { limit: DETAIL_PAGE_LIMIT })),
    readOptionalAgentData("agent policies", () => api.listAgentPolicies(agentId)),
  ]);
  document.querySelector("#facts-panel").textContent = renderSnapshot(
    facts.value,
    facts.error || "No facts snapshot.",
  );
  document.querySelector("#metrics-panel").textContent = renderSnapshot(
    metrics.value,
    metrics.error || "No metrics snapshot.",
  );
  document.querySelector("#facts-chart").innerHTML = facts.error
    ? `<div class="empty">${escapeHtml(facts.error)}</div>`
    : renderFactsInventory(facts.value, "No facts snapshot.");
  document.querySelector("#disk-inventory").innerHTML = facts.error
    ? `<div class="empty">${escapeHtml(facts.error)}</div>`
    : renderDiskInventory(facts.value, "No disk inventory.");
  document.querySelector("#metrics-chart").innerHTML = metricsHistory.error
    ? `<div class="empty">${escapeHtml(metricsHistory.error)}</div>`
    : renderTelemetryCharts(
        snapshotItems(metricsHistory.value),
        METRICS_CHARTS,
        "No metrics snapshots in the selected window.",
        state.metricsWindowMs,
      );
  document.querySelector("#drift-panel").innerHTML = drift.error
    ? `<div class="empty">${escapeHtml(drift.error)}</div>`
    : renderDrift(drift.value);
  document.querySelector("#drift-history").innerHTML = driftHistory.error
    ? `<div class="empty">${escapeHtml(driftHistory.error)}</div>`
    : renderDriftHistory(driftHistory.value);
  document.querySelector("#agent-logs").innerHTML = logs.error
    ? `<div class="empty">${escapeHtml(logs.error)}</div>`
    : renderAgentLogs(logs.value);
  document.querySelector("#agent-policies").innerHTML = agentPolicies.error
    ? `<div class="empty">${escapeHtml(agentPolicies.error)}</div>`
    : renderAgentPolicies(agentPolicies.value, agentId);
}

function snapshotItems(page) {
  return Array.isArray(page?.items) ? page.items : [];
}

async function readOptionalAgentData(label, load) {
  try {
    return { value: await load(), error: "" };
  } catch (error) {
    return {
      value: null,
      error: `Could not load ${label}. Refresh or check controller logs.`,
    };
  }
}

async function refreshAll() {
  if (!state.token && !adminAccounts.getSnapshot().user) {
    setStatus("Admin token is required.", "error");
    return;
  }
  setStatus("Loading controller data...");
  await loadAgents();
  await loadCatalogSources();
  const [jobs, enrollmentTokens, approvals, policies, remediations, signingStatus] = await Promise.all([
    api.listJobs(),
    ["operator", "viewer"].includes(adminAccounts.getSnapshot().user?.role) ? Promise.resolve([]) : api.listEnrollmentTokens(),
    api.listApprovals("pending"),
    api.listPolicies(),
    api.listRemediations({ limit: DETAIL_PAGE_LIMIT }),
    api.getControllerSigningRotationStatus(),
  ]);
  document.querySelector("#jobs-list").innerHTML = renderJobs(jobs);
  document.querySelector("#approvals-list").innerHTML = renderApprovals(approvals, jobs);
  wireApprovalButtons();
  state.remediations = Array.isArray(remediations) ? remediations : [];
  renderRemediationList();
  state.policies = Array.isArray(policies) ? policies : [];
  if (state.selectedPolicyId && !state.policies.some((policy) => policy.id === state.selectedPolicyId)) {
    state.selectedPolicyId = "";
  }
  if (!state.selectedPolicyId) {
    state.selectedPolicyId = state.policies[0]?.id || "";
  }
  renderPolicyList();
  document.querySelector("#enrollment-tokens-list").innerHTML = renderEnrollmentTokens(enrollmentTokens);
  document.querySelectorAll("[data-revoke-token-id]").forEach((button) => {
    button.addEventListener("click", () => {
      revokeEnrollmentToken(button.dataset.revokeTokenId).catch(showUiError);
    });
  });
  await loadAuditPage();
  document.querySelector("#signing-rotation-status").innerHTML =
    renderControllerSigningRotationStatus(signingStatus);
  const overview = document.querySelector("#overview-summary");
  if (overview) {
    overview.classList.remove("empty");
    overview.innerHTML = renderOverviewSummary({
      agents: state.agents,
      jobs,
      approvals,
      remediations: state.remediations,
    });
  }
  setStatus("Loaded latest controller data.", "ok");
}

/** Composes explicit catalog review/submission with DOM controls and the shared Job result callback. */
export function createCatalogJobPanel({ apiClient, elements, clock = globalThis, makeJobId, onCreated = () => {} }) {
  let route = "", authenticated = false, authGeneration = 0, selected = null, disposed = false;
  const listeners = [];
  const owner = createCatalogJobSubmission({ api: apiClient, clock, makeJobId, onCreated, onChange: render });
  const setText = (element, value) => { if (element.textContent !== value) element.textContent = value; };
  function render(view) {
    const focused = elements.review.ownerDocument?.activeElement;
    elements.panel.hidden = route !== "runbooks";
    setText(elements.status, !view.active ? "Open Runbooks and authenticate to prepare a catalog Job."
      : !view.eligible && !view.jobId ? "Choose a Runbook in the active, ready revision. Re-select after an active revision change."
      : view.message);
    const reference = view.submittedReference || view.reference;
    setText(elements.reference, reference
      ? `${view.submittedReference ? `Submitted Job: ${view.jobId}\n` : ""}Source: ${reference.source_id}\nCommit: ${reference.commit}\nPath: ${reference.path}\nSHA256: ${reference.checksum}`
      : "No executable catalog selection.");
    setText(elements.body, view.body);
    const previewHtml = view.preview
      ? `<p>${view.preview.ids.length} selected · ${view.preview.offline} offline · ${view.preview.disabled} disabled</p>`
        + view.preview.agents.map(agent => `<div class="catalog-job-target"><span><strong>${escapeHtml(agent.name)}</strong><small>${escapeHtml(agent.id)}</small></span><span>${escapeHtml(agent.status)} · ${agent.selected ? "Selected" : "Excluded"}</span></div>`).join("")
      : view.submittedTargetIds ? `<p>Submitted target snapshot (${view.submittedTargetIds.length}):</p><p>${view.submittedTargetIds.map(escapeHtml).join(", ")}</p>`
      : '<p class="muted">Review targets to see the exact Agent IDs this Job will use.</p>';
    if (elements.preview.innerHTML !== previewHtml) elements.preview.innerHTML = previewHtml;
    elements.confirm.checked = view.confirmed;
    elements.confirm.disabled = view.phase !== "prepared" || view.busy;
    const controls = [[elements.review, view.canPreview, view.phase === "reading"],
      [elements.submit, view.canSubmit, view.phase === "submitting"],
      [elements.check, view.canReconcile, view.phase === "checking"],
      [elements.retry, view.canRetry, view.phase === "submitting"]];
    for (const [button, enabled, inFlight] of controls) {
      button.disabled = !(enabled || (view.active && inFlight && focused === button));
      button.setAttribute("aria-disabled", String(!enabled));
    }
    elements.reset.disabled = !view.canReset;
    elements.check.hidden = !view.jobId || view.phase === "created";
    elements.retry.hidden = view.phase !== "missing" && !(view.phase === "submitting" && focused === elements.retry);
    elements.reset.hidden = !view.jobId && view.phase !== "error";
    elements.review.textContent = view.phase === "reading" ? "Reviewing..." : "Review document and targets";
    elements.submit.textContent = view.phase === "submitting" ? "Submitting..." : "Create catalog Job";
    elements.selector.disabled = !view.active || view.busy;
    elements.panel.setAttribute("aria-busy", String(view.busy));
    if (view.active && [elements.submit, elements.check, elements.retry].includes(focused)
        && (view.phase === "created" || view.phase === "error" || view.phase === "unknown")) {
      elements.status.focus({ preventScroll: true });
    }
  }
  function bind(element, event, handler) { element.addEventListener(event, handler); listeners.push([element, event, handler]); }
  function context() {
    owner.setContext({ route, authenticated, authGeneration, selection: selected?.selectedSource && selected?.selectedRevision && selected?.selectedDocument
      ? { sourceId: selected.selectedSource.id, activeCommit: selected.selectedSource.active_commit,
        commit: selected.selectedRevision.commit, state: selected.selectedRevision.state,
        kind: selected.selectedDocument.kind, path: selected.selectedDocument.path, checksum: selected.selectedDocument.checksum,
        stale: selected.selectionStale } : null });
  }
  bind(elements.selector, "input", () => owner.setSelector(elements.selector.value));
  bind(elements.confirm, "change", () => owner.setConfirmed(elements.confirm.checked));
  bind(elements.review, "click", () => { void owner.preview(); });
  bind(elements.submit, "click", () => { void owner.submit(); });
  bind(elements.check, "click", () => { void owner.reconcile(); });
  bind(elements.retry, "click", () => { void owner.retry(); });
  bind(elements.reset, "click", () => owner.reset());
  render(owner.getSnapshot());
  return {
    setContext(next) { if (disposed) return; route = next.route; authenticated = Boolean(next.authenticated); authGeneration = next.authGeneration ?? 0; context(); },
    setSelection(snapshot) { if (disposed) return; selected = snapshot; context(); },
    getSnapshot: owner.getSnapshot,
    dispose() { if (disposed) return; disposed = true; for (const [element, event, handler] of listeners) element.removeEventListener(event, handler); owner.dispose(); },
  };
}

/**
 * Connects body-free metadata pages to the existing Catalog lists. Selection only
 * changes local view state. Mutations remain explicit form/API effects outside
 * this panel; render never starts sync, activates a revision or creates a Job.
 */
export function createCatalogPanel({ apiClient, elements, clock = globalThis, onJobCreated = () => {} }) {
  const levels = ["sources", "revisions", "documents"];
  const keys = { sources: "catalogSourceId", revisions: "catalogCommit", documents: "catalogPath" };
  const selectors = { sources: "[data-catalog-source-id]", revisions: "[data-catalog-commit]", documents: "[data-catalog-path]" };
  const emptyMessages = { sources: "No catalog sources registered.", revisions: "No synced revisions for this source.", documents: "No validated documents in this revision." };
  const listeners = [];
  const renderedMarkup = new Map();
  let disposed = false;
  const explorer = createCatalogExplorer({ api: apiClient, clock, onChange: render });
  const actionPanel = elements.actions ? createCatalogActionPanel({ apiClient, clock, elements: elements.actions,
    onCommitted: action => { if (action === "register") void explorer.load("sources"); } }) : null;
  const jobPanel = elements.execution ? createCatalogJobPanel({ apiClient, clock, elements: elements.execution, onCreated: onJobCreated }) : null;

  function guidance(error) {
    return error.kind === "authentication" ? "Authenticate again with an admin token."
      : error.kind === "forbidden" ? "Permission denied. Check your catalog access."
      : error.kind === "not_found" ? "Catalog read endpoint not found. Check the Controller version."
      : error.kind === "invalid_response" ? "Catalog metadata could not be verified. Refresh before continuing."
      : error.kind === "timeout" ? "Catalog read timed out. Retry when the Controller is reachable."
      : "Catalog read failed. Retry or check the Controller connection.";
  }
  function writeText(element, value) { if (element.textContent !== value) element.textContent = value; }
  function render(snapshot) {
    for (const level of levels) {
      const view = elements[level], page = snapshot[level], focused = view.list.ownerDocument?.activeElement;
      const enabled = snapshot.active && (level === "sources" || Boolean(snapshot.selectedSource))
        && (level !== "documents" || Boolean(snapshot.selectedRevision));
      const busy = page.phase === "loading";
      const html = !snapshot.active ? '<div class="empty">Open Runbooks or Policies and authenticate to browse catalog metadata.</div>'
        : level === "sources" ? renderCatalogSources(page.items)
        : level === "revisions" ? renderCatalogRevisions(page.items, "", snapshot.selectedSource?.active_commit || "")
        : renderCatalogDocuments(page.items);
      // Reading innerHTML back would include our dynamic aria-pressed/class updates.
      if (renderedMarkup.get(level) !== html) { view.list.innerHTML = html; renderedMarkup.set(level, html); }
      // Selection is a DOM attribute update, preserving the focused row's identity.
      const selectedKey = level === "sources" ? snapshot.selectedSource?.id
        : level === "revisions" ? snapshot.selectedRevision?.commit : snapshot.selectedDocument?.path;
      view.list.querySelectorAll(selectors[level]).forEach(row => {
        const selected = row.dataset[keys[level]] === selectedKey;
        row.classList.toggle("selected", selected); row.setAttribute("aria-pressed", String(selected));
      });
      const message = !snapshot.active ? "Catalog reads are inactive."
        : !enabled ? level === "documents" ? "Choose a revision to read document metadata." : "Choose a source to read revisions."
        : page.error ? `${guidance(page.error)} The last loaded page is unchanged.`
        : busy ? "Loading catalog metadata..."
        : page.phase === "ready" ? `Page ${page.pageNumber}. ${page.items.length ? `${page.items.length} item(s). ${page.hasNext ? "More pages available." : "End of the current list."}` : emptyMessages[level]}`
        : "Choose a catalog item to continue.";
      writeText(view.status, message);
      const conditions = { first: enabled, next: enabled && page.phase === "ready" && page.hasNext, retry: enabled && Boolean(page.error) };
      for (const action of ["first", "next", "retry"]) {
        const button = view[action];
        button.disabled = busy ? focused !== button : !conditions[action];
        writeText(button, busy && focused === button ? "Loading page..." : action === "first" ? "First page" : action === "next" ? "Next page" : "Retry");
      }
      if (focused === view.next && view.next.disabled) view.list.focus({ preventScroll: true });
    }
    writeText(elements.selection, snapshot.selectedSource
      ? `Source: ${snapshot.selectedSource.id} · Revision: ${snapshot.selectedRevision?.commit || "Not selected"} · Document: ${snapshot.selectedDocument?.path || "Not selected"}${snapshot.selectionStale ? ". The active revision changed. Review and reselect before execution." : ""}`
      : "No catalog selection. Choose a source, revision, then document.");
    actionPanel?.setSelection(snapshot);
    jobPanel?.setSelection(snapshot);
  }
  function bind(element, handler) { element.addEventListener("click", handler); listeners.push([element, handler]); }
  for (const level of levels) {
    const view = elements[level];
    bind(view.list, event => {
      const row = event.target?.closest?.(selectors[level]);
      if (!row || !view.list.contains(row)) return;
      const value = row.dataset[keys[level]];
      if (level === "sources") void explorer.selectSource(value);
      else if (level === "revisions") void explorer.selectRevision(value);
      else explorer.selectDocument(value);
    });
    for (const action of ["first", "next", "retry"]) bind(view[action], () => {
      if (!disposed && explorer.getSnapshot()[level].phase !== "loading") void explorer.load(level, { next: action === "next", retry: action === "retry" });
    });
  }
  render(explorer.getSnapshot());
  return {
    setContext: next => { actionPanel?.setContext(next); jobPanel?.setContext(next); return explorer.setContext(next); },
    refreshSources: () => explorer.load("sources"),
    getSnapshot: () => explorer.getSnapshot(),
    dispose() {
      disposed = true;
      actionPanel?.dispose();
      jobPanel?.dispose();
      for (const [element, handler] of listeners) element.removeEventListener("click", handler);
      explorer.dispose(); render(explorer.getSnapshot());
    },
  };
}

export function renderCatalogSources(sources, selectedSourceId = "") {
  if (!Array.isArray(sources) || sources.length === 0) {
    return '<div class="empty">No catalog sources registered.</div>';
  }
  return sources
    .map((source) => {
      const selected = source.id === selectedSourceId ? " selected" : "";
      const active = source.active_commit
        ? `<span class="status-pill active">active ${escapeHtml(source.active_commit.slice(0, 12))}</span>`
        : '<span class="status-pill">no active revision</span>';
      return `<button class="catalog-row${selected}" type="button" data-catalog-source-id="${escapeHtml(source.id)}"><span><strong>${escapeHtml(source.id)}</strong><small>${escapeHtml(source.reference)}</small></span>${active}</button>`;
    })
    .join("");
}

export function renderCatalogRevisions(revisions, selectedCommit = "", activeCommit = "") {
  if (!Array.isArray(revisions) || revisions.length === 0) {
    return '<div class="empty">No synced revisions for this source.</div>';
  }
  return revisions
    .map((revision) => {
      const selected = revision.commit === selectedCommit ? " selected" : "";
      const active = revision.commit === activeCommit ? '<span class="status-pill active">active</span>' : "";
      const failure = revision.failure ? `<small>${escapeHtml(revision.failure)}</small>` : "";
      return `<button class="catalog-row${selected}" type="button" data-catalog-commit="${escapeHtml(revision.commit)}"><span><strong>${escapeHtml(revision.commit.slice(0, 12))}…${escapeHtml(revision.commit.slice(-8))}</strong><small>${escapeHtml(revision.state)} · ${escapeHtml(revision.document_count)} documents</small>${failure}</span>${active}</button>`;
    })
    .join("");
}

export function renderCatalogDocuments(documents) {
  if (!Array.isArray(documents) || documents.length === 0) {
    return '<div class="empty">No validated runbook or policy documents in this revision.</div>';
  }
  return documents
    .map(
      (document) =>
        `<button class="catalog-row catalog-document" type="button" data-catalog-path="${escapeHtml(document.path)}"><span class="status-pill">${escapeHtml(document.kind)}</span><span><strong>${escapeHtml(document.path)}</strong><small>checksum ${escapeHtml(document.checksum.slice(0, 12))}</small></span></button>`,
    )
    .join("");
}

/** Binds explicit Catalog commands and native activation confirmation to one owned view. */
export function createCatalogActionPanel({ apiClient, elements, clock = globalThis, onCommitted = () => {} }) {
  let context = { route: "", authenticated: false }, selected = null, selectionKey = "", disposed = false;
  let focusAfterConfirmation = null, confirmationTrigger = null, contextKey = "";
  const listeners = [];
  const owner = createCatalogActions({ api: apiClient, clock, onCommitted, onChange: render });
  function render(view) {
    elements.status.textContent = view.message || (view.active
      ? "Start sync accepts a request. Check its operation to see the actual result."
      : "Open Runbooks or Policies and authenticate to manage the Catalog.");
    elements.status.dataset.tone = view.tone;
    elements.operation.textContent = view.operation
      ? `Source: ${view.operation.source_id} · Operation: ${view.operation.id} · State: ${view.operation.state}${view.operation.commit ? ` · Commit: ${view.operation.commit}` : ""}`
      : "No verified sync operation loaded.";
    const observing = ["reading", "waiting"].includes(view.observation);
    elements.form.querySelectorAll('button[name="catalog-action"]').forEach(button => { button.disabled = !view.active || view.busy || Boolean(view.confirmation) || observing; });
    elements.check.disabled = !view.active || view.busy || Boolean(view.confirmation) || observing;
    elements.stop.disabled = !observing;
    elements.resume.disabled = !view.canResume || Boolean(view.confirmation);
    elements.confirm.disabled = view.busy || !view.confirmation;
    if (view.confirmation) {
      elements.details.textContent = `Source: ${view.confirmation.sourceId}\nReady commit: ${view.confirmation.commit}\nLast observed active commit: ${view.confirmation.activeCommit || "None"}\nActivate this exact revision? This does not execute a Job. Another administrator may change the active revision independently.`;
      if (!elements.dialog.open) elements.dialog.showModal();
    } else if (elements.dialog.open) elements.dialog.close();
    if (focusAfterConfirmation && !view.confirmation && !view.busy) {
      if (view.active) (focusAfterConfirmation === "trigger" ? confirmationTrigger : elements.status)?.focus?.({ preventScroll: true });
      focusAfterConfirmation = null;
    }
  }
  function bind(element, type, handler) { element.addEventListener(type, handler); listeners.push([element, type, handler]); }
  function input() { return Object.fromEntries(Object.entries(elements.fields).map(([key, field]) => [key, field.value.trim()])); }
  bind(elements.form, "submit", event => {
    event.preventDefault();
    if (event.submitter?.value === "activate") confirmationTrigger = event.submitter;
    if (!disposed) void owner.submit(event.submitter?.value || "", input());
  });
  bind(elements.check, "click", () => { if (!disposed) void owner.resumeSync(input()); });
  bind(elements.stop, "click", () => owner.stopObservation());
  bind(elements.resume, "click", () => { if (!disposed) void owner.resumeSync(); });
  bind(elements.confirm, "click", () => { if (!disposed) { focusAfterConfirmation = "status"; void owner.confirmActivation(); } });
  const cancel = () => { focusAfterConfirmation = "trigger"; owner.cancelActivation(); };
  bind(elements.cancel, "click", cancel);
  bind(elements.dialog, "cancel", event => { event.preventDefault(); cancel(); });
  function updateContext() {
    const next = { ...context, selection: selected }, key = JSON.stringify(next);
    if (key !== contextKey) { contextKey = key; focusAfterConfirmation = null; }
    owner.setContext(next);
  }
  render(owner.getSnapshot());
  return {
    setContext(next) { context = next; updateContext(); },
    setSelection(snapshot) {
      selected = snapshot.selectedSource ? { sourceId: snapshot.selectedSource.id,
        commit: snapshot.selectedRevision?.commit || null, state: snapshot.selectedRevision?.state || null,
        stale: snapshot.selectionStale, activeCommit: snapshot.selectedSource.active_commit,
        documentPath: snapshot.selectedDocument?.path || null } : null;
      const key = JSON.stringify([selected?.sourceId, selected?.commit]);
      if (key !== selectionKey && selected) {
        elements.fields.sourceId.value = selected.sourceId;
        elements.fields.commit.value = selected.commit || "";
      }
      selectionKey = key; updateContext();
    },
    dispose() {
      disposed = true; focusAfterConfirmation = null; owner.dispose();
      for (const [element, type, handler] of listeners) element.removeEventListener(type, handler);
      render(owner.getSnapshot());
    },
  };
}

async function loadCatalogSources() {
  await catalogPanel?.refreshSources();
}

function renderPolicyList() {
  const list = document.querySelector("#policies-list");
  if (list) {
    list.innerHTML = renderPolicies(state.policies, state.selectedPolicyId);
  }
  syncAgentActions();
}

function wireApprovalButtons() {
  document.querySelectorAll("[data-approve-approval-id]").forEach((button) => {
    button.disabled = adminAccounts.getSnapshot().user?.role === "viewer";
    button.addEventListener("click", () => {
      decideApproval(button.dataset.approveApprovalId, "approve").catch((error) =>
        setStatus(error.message, "error"),
      );
    });
  });
  document.querySelectorAll("[data-reject-approval-id]").forEach((button) => {
    button.disabled = adminAccounts.getSnapshot().user?.role === "viewer";
    button.addEventListener("click", () => {
      decideApproval(button.dataset.rejectApprovalId, "reject").catch((error) =>
        setStatus(error.message, "error"),
      );
    });
  });
}

async function loadApprovalsJobsAndAudit() {
  const [approvals, jobs, remediations] = await Promise.all([
    api.listApprovals("pending"),
    api.listJobs(),
    api.listRemediations({ limit: DETAIL_PAGE_LIMIT }),
  ]);
  document.querySelector("#approvals-list").innerHTML = renderApprovals(approvals, jobs);
  wireApprovalButtons();
  document.querySelector("#jobs-list").innerHTML = renderJobs(jobs);
  state.remediations = Array.isArray(remediations) ? remediations : [];
  renderRemediationList();
  await loadAuditPage();
}

function renderRemediationList() {
  const list = document.querySelector("#remediations-list");
  if (!list) {
    return;
  }
  list.innerHTML = renderRemediations(state.remediations, state.selectedRemediationId);
}

function selectedRemediation() {
  return state.remediations.find((item) => item.id === state.selectedRemediationId) || null;
}

function syncRemediationForm(remediation) {
  if (!remediation) {
    return;
  }
  document.querySelector("#remediation-id").value = remediation.id || "";
  if (remediation.job_id) {
    document.querySelector("#remediation-job-id").value = remediation.job_id;
  }
  document.querySelector("#remediation-result").textContent = renderRemediationActionResult(remediation);
}

function readRemediationForm() {
  return {
    remediationId: document.querySelector("#remediation-id")?.value.trim() || "",
    approvalId: document.querySelector("#remediation-approval-id")?.value.trim() || "",
    jobId: document.querySelector("#remediation-job-id")?.value.trim() || "",
    runbookDocument: document.querySelector("#remediation-runbook-document")?.value || "",
  };
}

function optionalString(value) {
  const text = String(value ?? "").trim();
  return text ? text : undefined;
}

function requireRemediationId(form) {
  if (!form.remediationId) {
    throw new Error("Select or enter a remediation request first.");
  }
}

function requireRemediationJobId(form) {
  if (!form.jobId) {
    throw new Error("Enter the remediation job id.");
  }
}

export function renderRemediationActionResult(response) {
  const remediation = response?.remediation || response || {};
  const lines = [
    `remediation_id=${remediation.id || ""}`,
    `policy_id=${remediation.policy_id || ""}`,
    `agent_id=${remediation.agent_id || ""}`,
    `status=${remediation.status || ""}`,
    `runbook_ref=${remediation.runbook_ref || ""}`,
    `job_id=${remediation.job_id || response?.job_id || ""}`,
  ];
  if (response?.approval) {
    lines.push(`approval_id=${response.approval.id || ""}`);
    lines.push(`approval_status=${response.approval.status || ""}`);
  }
  if (response?.assignment_count !== undefined) {
    lines.push(`assignment_count=${response.assignment_count}`);
  }
  return lines.join("\n");
}

async function loadRemediations() {
  syncAdminTokenFromInput({ requireToken: true });
  const remediations = await api.listRemediations({ limit: DETAIL_PAGE_LIMIT });
  state.remediations = Array.isArray(remediations) ? remediations : [];
  if (
    state.selectedRemediationId &&
    !state.remediations.some((remediation) => remediation.id === state.selectedRemediationId)
  ) {
    state.selectedRemediationId = "";
  }
  renderRemediationList();
  if (state.selectedRemediationId) {
    syncRemediationForm(selectedRemediation());
  }
}

async function requestRemediationApproval() {
  syncAdminTokenFromInput({ requireToken: true });
  const form = readRemediationForm();
  requireRemediationId(form);
  const response = await api.createRemediationApprovalRequest(form.remediationId, {
    approval_id: optionalString(form.approvalId),
    job_id: optionalString(form.jobId),
    reason: "requested from Web Admin",
    expires_in_seconds: 300,
  });
  state.selectedRemediationId = response?.remediation?.id || form.remediationId;
  document.querySelector("#remediation-result").textContent = renderRemediationActionResult(response);
  setStatus(`Requested remediation approval for ${state.selectedRemediationId}.`, "ok");
  await loadApprovalsJobsAndAudit();
}

async function approveRemediationJob() {
  syncAdminTokenFromInput({ requireToken: true });
  const form = readRemediationForm();
  requireRemediationId(form);
  requireRemediationJobId(form);
  if (!form.approvalId) {
    throw new Error("Enter the remediation approval id.");
  }
  if (!form.runbookDocument.trim()) {
    throw new Error("Enter the approved remediation runbook YAML.");
  }
  const response = await api.approveRemediationJob(form.remediationId, {
    approval_id: form.approvalId,
    job_id: form.jobId,
    runbook_document: form.runbookDocument,
    timeout_seconds: 30,
    expires_in_seconds: 300,
    reason: "approved from Web Admin",
  });
  state.selectedRemediationId = response?.remediation?.id || form.remediationId;
  const jobId = response?.job_id || form.jobId;
  jobObservation?.select(jobId);
  document.querySelector("#remediation-result").textContent = renderRemediationActionResult(response);
  setStatus(`Created remediation job ${jobId}.`, "ok");
  await loadApprovalsJobsAndAudit();
}

async function decideApproval(id, action) {
  syncAdminTokenFromInput({ requireToken: true });
  if (!id) {
    throw new Error("Select an approval request first.");
  }
  const reason =
    typeof globalThis.prompt === "function"
      ? globalThis.prompt(`${action === "approve" ? "Approve" : "Reject"} reason`, "")
      : "";
  if (reason === null) {
    return;
  }
  let decision = null;
  if (action === "approve") {
    decision = await api.approveApproval(id, { reason: reason || "" });
  } else {
    decision = await api.rejectApproval(id, { reason: reason || "" });
  }
  setStatus(`${action === "approve" ? "Approved" : "Rejected"} ${id}.`, "ok");
  await loadApprovalsJobsAndAudit();
  const jobIdToPoll = approvalDecisionJobToPoll(action, decision);
  if (jobIdToPoll) {
    jobObservation?.select(jobIdToPoll);
  }
}

async function expireDueApprovals() {
  syncAdminTokenFromInput({ requireToken: true });
  const response = await api.expireApprovals();
  setStatus(`Expired ${response?.expired_count ?? 0} approval request(s).`, "ok");
  await loadApprovalsJobsAndAudit();
}

async function loadPolicies() {
  const policies = await api.listPolicies();
  state.policies = Array.isArray(policies) ? policies : [];
  if (state.selectedPolicyId && !state.policies.some((policy) => policy.id === state.selectedPolicyId)) {
    state.selectedPolicyId = "";
  }
  if (!state.selectedPolicyId) {
    state.selectedPolicyId = state.policies[0]?.id || "";
  }
  renderPolicyList();
}

async function submitPolicy(form) {
  syncAdminTokenFromInput({ requireToken: true });
  const data = new FormData(form);
  const request = buildPolicySaveRequest({ source: data.get("policy-source") });
  const saved = await api.savePolicy(request);
  state.selectedPolicyId = saved.id;
  setStatus(`Saved policy ${saved.id}.`, "ok");
  await loadPolicies();
}

async function assignSelectedPolicy() {
  syncAdminTokenFromInput({ requireToken: true });
  const request = buildPolicyAssignmentRequest({
    policyId: state.selectedPolicyId,
    agentId: state.selectedAgentId,
  });
  await api.assignPolicy(state.selectedPolicyId, request);
  setStatus(`Assigned policy ${state.selectedPolicyId} to ${state.selectedAgentId}.`, "ok");
  await refreshSelectedAgent();
}

async function scheduleSelectedPolicy() {
  syncAdminTokenFromInput({ requireToken: true });
  const request = buildPolicyScheduleRequest({
    policyId: state.selectedPolicyId,
    agentId: state.selectedAgentId,
    intervalSeconds: document.querySelector("#policy-schedule-interval")?.value,
  });
  await api.schedulePolicyDrift(state.selectedPolicyId, request);
  setStatus(`Scheduled drift for ${state.selectedPolicyId} on ${state.selectedAgentId}.`, "ok");
  await refreshSelectedAgent();
}

async function submitEnrollmentToken(form) {
  syncAdminTokenFromInput({ requireToken: true });
  const data = new FormData(form);
  const request = buildEnrollmentTokenRequest({
    labels: data.get("labels"),
    maxUses: data.get("max-uses"),
    expiresInSeconds: data.get("expires-in-seconds"),
  });
  const response = await api.createEnrollmentToken(request);
  state.createdEnrollmentToken = response;
  document.querySelector("#created-enrollment-token").textContent = renderCreatedEnrollmentToken(
    response,
    data.get("controller-url")?.toString() || "",
    data.get("agent-name")?.toString() || "",
  );
  setStatus(`Created enrollment token ${response.id}. Copy the token before refreshing.`, "ok");
  await loadEnrollmentTokens();
}

async function loadEnrollmentTokens() {
  const enrollmentTokens = await api.listEnrollmentTokens();
  document.querySelector("#enrollment-tokens-list").innerHTML = renderEnrollmentTokens(enrollmentTokens);
  document.querySelectorAll("[data-revoke-token-id]").forEach((button) => {
    button.addEventListener("click", () => {
      revokeEnrollmentToken(button.dataset.revokeTokenId).catch(showUiError);
    });
  });
}

async function revokeEnrollmentToken(id) {
  syncAdminTokenFromInput({ requireToken: true });
  await api.revokeEnrollmentToken(id);
  setStatus(`Revoked enrollment token ${id}.`, "ok");
  await loadEnrollmentTokens();
}

async function revokeSelectedAgentKey() {
  syncAdminTokenFromInput({ requireToken: true });
  const agent = selectedAgent();
  if (!agent) {
    throw new Error("Select an agent first.");
  }
  const label = agent.name || agent.id;
  if (
    typeof globalThis.confirm === "function" &&
    !globalThis.confirm(`Revoke agent ${label}? This disables its current key.`)
  ) {
    return;
  }
  const updated = await api.revokeAgentKey(agent.id);
  if (updated) {
    state.agents = state.agents.map((item) => (item.id === updated.id ? updated : item));
  }
  document.querySelector("#agents-list").innerHTML = renderAgents(state.agents, state.selectedAgentId);
  syncAgentActions();
  await refreshSelectedAgent();
  await loadAuditPage();
  setStatus(`Revoked agent ${label}.`, "ok");
}

async function submitStagedTrustBundle(form) {
  syncAdminTokenFromInput({ requireToken: true });
  const data = new FormData(form);
  const request = buildStagedTrustBundleRequest({
    previousPublicKeyPath: data.get("previous-public-key-path"),
    agentIds: data.get("agent-ids"),
    batchSize: data.get("batch-size"),
    maxFailures: data.get("max-failures"),
    ackTimeoutSeconds: data.get("ack-timeout-seconds"),
  });
  const response = await api.stageControllerSigningTrustBundle(request);
  const resultElement = document.querySelector("#staged-trust-bundle-result");
  if (resultElement) {
    resultElement.classList.remove("empty");
    resultElement.innerHTML = renderStagedTrustBundleResult(response);
  }
  setStatus(
    `Ran staged signing tick: ${response?.rollout_state || "unknown"} (${response?.attempted_count ?? 0} attempted).`,
    "ok",
  );
  await Promise.all([loadSigningRotationStatus(), loadAuditPage()]);
}

async function previewTargets(selector, targetSelector) {
  syncAdminTokenFromInput({ requireToken: true });
  const request = buildSelectorPreviewRequest({ selector });
  const target = document.querySelector(targetSelector);
  if (target) {
    target.classList.remove("empty");
    target.innerHTML = '<div class="empty">Loading selector preview...</div>';
  }
  try {
    const preview = await api.previewSelector(request);
    if (target) {
      target.innerHTML = renderSelectorPreview(preview);
    }
    return preview;
  } catch (error) {
    if (target) {
      target.innerHTML = `<div class="preview-warning">${escapeHtml(error.message || "Selector preview failed.")}</div>`;
    }
    throw error;
  }
}

function requireDispatchablePreviewTargets(preview) {
  if (selectorPreviewSelectedCount(preview) < 1) {
    throw new Error("Selector preview returned no dispatchable targets.");
  }
}

async function submitCommand(form) {
  syncAdminTokenFromInput({ requireToken: true });
  const data = new FormData(form);
  const selector = data.get("selector");
  const targetSelector = String(selector ?? "").trim();
  if (targetSelector) {
    requireDispatchablePreviewTargets(await previewTargets(targetSelector, "#command-target-preview"));
  }
  const request = buildCommandJobRequest({
    agentId: state.selectedAgentId,
    selector,
    program: data.get("program"),
    args: data.get("args"),
    confirmed: data.get("confirm-risk") === "on",
  });
  const response = await directSubmissions.command.submit(request);
  if (!response) return;
  jobObservation?.select(response.job_id);
  const pendingApproval = response.status === "pending_approval" || response.approval_request_id;
  if (pendingApproval) {
    setStatus(`Created ${response.job_id}; approval ${response.approval_request_id} is required.`, "ok");
    await loadApprovalsJobsAndAudit();
    return;
  }
  setStatus(`Created ${response.job_id} for ${response.target_count} target.`, "ok");
}

async function submitRunbook(form) {
  syncAdminTokenFromInput({ requireToken: true });
  const data = new FormData(form);
  const selector = data.get("selector");
  const targetSelector = String(selector ?? "").trim();
  if (targetSelector) {
    requireDispatchablePreviewTargets(await previewTargets(targetSelector, "#runbook-target-preview"));
  }
  const request = buildRunbookJobRequest({
    agentId: state.selectedAgentId,
    selector,
    document: data.get("runbook-document"),
    confirmed: data.get("confirm-risk") === "on",
  });
  const response = await directSubmissions.runbook.submit(request);
  if (!response) return;
  jobObservation?.select(response.job_id);
  const pendingApproval = response.status === "pending_approval" || response.approval_request_id;
  const statusText = pendingApproval
    ? `Runbook job ${response.job_id} requires approval ${response.approval_request_id}.`
    : `Runbook job ${response.job_id} created.`;
  document.querySelector("#runbook-result").textContent = statusText;
  setStatus(statusText, "ok");
  await loadApprovalsJobsAndAudit();
}

export async function pollJobOutputOnce(apiClient, jobId) {
  const [job, chunks] = await Promise.all([apiClient.getJob(jobId), apiClient.getJobOutput(jobId)]);
  if (Array.isArray(chunks) && chunks.length > 0) {
    return {
      text: renderJobOutput(chunks, { jobId, job }),
      terminal: isTerminalJob(job),
    };
  }
  return {
    text: renderJobOutputStatus(job || { id: jobId }, {
      jobId,
      attempt: 1,
      maxAttempts: 1,
    }),
    terminal: isTerminalJob(job),
  };
}

export function renderJobOutputAfterPolling({ job = null, chunks = [], jobId = "" } = {}) {
  if (Array.isArray(chunks) && chunks.length > 0) {
    return renderJobOutput(chunks, { jobId, job });
  }
  return renderJobOutputStatus(job || { id: jobId }, {
    jobId,
    attempt: JOB_OUTPUT_POLL_ATTEMPTS,
    maxAttempts: JOB_OUTPUT_POLL_ATTEMPTS,
  });
}

async function handleJobArtifactClick(event) {
  const button = event.target?.closest?.("[data-artifact-id]");
  if (!button) {
    return;
  }
  const artifactId = button.dataset.artifactId || "";
  const jobId = button.dataset.artifactJobId || jobObservation?.getJobId() || "";
  if (!artifactId || !jobId) {
    return;
  }
  await jobObservation?.showArtifact(jobId, artifactId);
}

function boot() {
  wireAccountForms();
  void restoreAdminSession();
  applyAdminRoute();
  globalThis.addEventListener?.("hashchange", () => { applyAdminRoute({ focus: true }); onAccountState(adminAccounts.getSnapshot()); if(currentAdminRoute() === "settings") void refreshAccountMetadata(); });
  globalThis.addEventListener?.("pagehide", () => {
    adminAccounts.suspend();
    for (const submission of Object.values(directSubmissions)) submission.setContext({ authenticated: false, authGeneration: api.getAuthGeneration() });
    jobObservation?.setContext(adminViewContext(""));
    void catalogPanel?.setContext(adminViewContext(""));
  });
  globalThis.addEventListener?.("pageshow", event => {
    applyAdminRoute(); onAccountState(adminAccounts.getSnapshot());
    if (event.persisted) void restoreAdminSession();
  });
  for (const [kind, submission] of Object.entries(directSubmissions)) {
    document.querySelector("#" + kind + "-check-submission")?.addEventListener("click", () => {
      void submission.check().then(job => { if (job) jobObservation?.select(job.id); });
    });
  }
  const form = document.querySelector("#admin-auth");
  if (!form) {
    return;
  }
  const warning = document.querySelector("#transport-warning");
  if (warning && globalThis.location?.protocol === "http:") {
    warning.hidden = false;
  }
  const transport = document.querySelector(".transport-chip");
  if (transport) {
    transport.textContent = globalThis.location?.protocol === "https:" ? "HTTPS" : "HTTP · test only";
    transport.dataset.secure = String(globalThis.location?.protocol === "https:");
  }
  document.querySelector("#job-artifacts")?.addEventListener("click", (event) => {
    handleJobArtifactClick(event).catch(showUiError);
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    setAdminToken(readAdminTokenInput());
    refreshAll().catch(showUiError);
  });
  document.querySelector("#clear-admin-token")?.addEventListener("click", () => {
    setAdminToken("");
    document.querySelector("#admin-token").value = "";
    setStatus("Admin token cleared. Job observation stopped; running jobs are not canceled.");
  });
  document.querySelector("#admin-token")?.addEventListener("input", () => {
    if (state.token && readAdminTokenInput() !== state.token) setAdminToken("");
  });
  document.querySelector("#jobs-list")?.addEventListener("click", (event) => {
    const button = event.target?.closest?.("[data-job-id]");
    if (button?.dataset?.jobId) jobObservation?.select(button.dataset.jobId);
  });
  const runForm = document.querySelector("#run-command-form");
  if (runForm) {
    runForm.addEventListener("submit", (event) => {
      event.preventDefault();
      submitCommand(runForm).catch(showUiError);
    });
    document.querySelector("#preview-command-targets")?.addEventListener("click", () => {
      const data = new FormData(runForm);
      previewTargets(data.get("selector"), "#command-target-preview")
        .then((preview) => {
          setStatus(
            `Previewed ${selectorPreviewSelectedCount(preview)} dispatchable target(s) from ${preview?.matched_count ?? 0} match(es).`,
            "ok",
          );
        })
        .catch(showUiError);
    });
  }
  const runbookForm = document.querySelector("#runbook-form");
  if (runbookForm) {
    runbookForm.addEventListener("submit", (event) => {
      event.preventDefault();
      submitRunbook(runbookForm).catch(showUiError);
    });
    document.querySelector("#preview-runbook-targets")?.addEventListener("click", () => {
      const data = new FormData(runbookForm);
      previewTargets(data.get("selector"), "#runbook-target-preview")
        .then((preview) => {
          setStatus(
            `Previewed ${selectorPreviewSelectedCount(preview)} dispatchable target(s) from ${preview?.matched_count ?? 0} match(es).`,
            "ok",
          );
        })
        .catch(showUiError);
    });
  }
  const policyForm = document.querySelector("#policy-form");
  if (policyForm) {
    policyForm.addEventListener("submit", (event) => {
      event.preventDefault();
      submitPolicy(policyForm).catch(showUiError);
    });
  }
  const agentsList = document.querySelector("#agents-list");
  if (agentsList) {
    agentsList.addEventListener("click", handleAgentsListClick);
  }
  const policiesList = document.querySelector("#policies-list");
  if (policiesList) {
    policiesList.addEventListener("click", (event) => {
      const button = event.target?.closest?.("[data-policy-id]");
      if (!button?.dataset?.policyId) {
        return;
      }
      state.selectedPolicyId = button.dataset.policyId;
      renderPolicyList();
    });
  }
  document.querySelector("#revoke-agent-key")?.addEventListener("click", () => {
    revokeSelectedAgentKey().catch(showUiError);
  });
  document.querySelector("#refresh-signing-rotation")?.addEventListener("click", () => {
    try {
      syncAdminTokenFromInput({ requireToken: true });
      loadSigningRotationStatus()
        .then(() => setStatus("Refreshed controller signing status.", "ok"))
        .catch(showUiError);
    } catch (error) {
      setStatus(error.message, "error");
    }
  });
  const stagedTrustBundleForm = document.querySelector("#staged-trust-bundle-form");
  if (stagedTrustBundleForm) {
    stagedTrustBundleForm.addEventListener("submit", (event) => {
      event.preventDefault();
      submitStagedTrustBundle(stagedTrustBundleForm).catch(showUiError);
    });
  }
  document.querySelector("#expire-approvals")?.addEventListener("click", () => {
    expireDueApprovals().catch(showUiError);
  });
  document.querySelector("#refresh-catalog")?.addEventListener("click", () => {
    loadCatalogSources().catch(showUiError);
  });
  document.querySelector("#refresh-audit")?.addEventListener("click", () => {
    loadAuditPage().catch(showUiError);
  });
  document.querySelector("#load-more-audit")?.addEventListener("click", () => {
    loadAuditPage({ append: true }).catch(showUiError);
  });
  document.querySelector("#remediations-list")?.addEventListener("click", (event) => {
    const button = event.target?.closest?.("[data-remediation-id]");
    if (!button?.dataset?.remediationId) {
      return;
    }
    state.selectedRemediationId = button.dataset.remediationId;
    renderRemediationList();
    syncRemediationForm(selectedRemediation());
  });
  document.querySelector("#refresh-remediations")?.addEventListener("click", () => {
    loadRemediations()
      .then(() => setStatus("Refreshed remediation requests.", "ok"))
      .catch(showUiError);
  });
  document.querySelector("#request-remediation-approval")?.addEventListener("click", () => {
    requestRemediationApproval().catch(showUiError);
  });
  document.querySelector("#approve-remediation")?.addEventListener("click", () => {
    approveRemediationJob().catch(showUiError);
  });
  document.querySelector("#assign-policy")?.addEventListener("click", () => {
    assignSelectedPolicy().catch(showUiError);
  });
  document.querySelector("#schedule-policy")?.addEventListener("click", () => {
    scheduleSelectedPolicy().catch(showUiError);
  });
  document.querySelector("#metrics-range")?.addEventListener("change", (event) => {
    const value = Number.parseInt(event.target?.value || "", 10);
    state.metricsWindowMs = Number.isInteger(value) && value > 0 ? value : DEFAULT_TELEMETRY_WINDOW_MS;
    if (state.selectedAgentId) {
      refreshSelectedAgent().catch(showUiError);
    }
  });
  document.querySelector("#refresh-telemetry")?.addEventListener("click", () => {
    try {
      syncAdminTokenFromInput({ requireToken: true });
      if (!state.selectedAgentId) {
        throw new Error("Select an agent before refreshing telemetry.");
      }
      setStatus(`Refreshing telemetry for ${state.selectedAgentId}...`);
      refreshSelectedAgent()
        .then(() => setStatus(`Refreshed telemetry for ${state.selectedAgentId}.`, "ok"))
        .catch(showUiError);
    } catch (error) {
      setStatus(error.message, "error");
    }
  });
  const enrollmentForm = document.querySelector("#enrollment-token-form");
  if (enrollmentForm) {
    enrollmentForm.addEventListener("submit", (event) => {
      event.preventDefault();
      submitEnrollmentToken(enrollmentForm).catch(showUiError);
    });
  }
}

if (typeof document !== "undefined") {
  boot();
}
