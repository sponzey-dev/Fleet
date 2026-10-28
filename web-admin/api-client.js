/** @file Authenticated HTTP effects; optional snapshots and required Job reads have distinct missing-data semantics. */
export const API_SCHEMA_VERSION = "mvp-1";

/** HTTP failure metadata for retry/reauthentication decisions, without retaining a response body or credentials. */
export class ApiHttpError extends Error {
  /** @param {string} message Safe message. @param {number} status HTTP status. @param {boolean} [catalogRejected] Verified pre-commit catalog rejection. */
  constructor(message, status, catalogRejected = false) {
    super(message);
    this.name = "ApiHttpError";
    this.status = status;
    this.catalogRejected = catalogRejected;
  }
}

function encodePathValue(value) {
  return encodeURIComponent(String(value ?? ""));
}

function pageQuery({ limit, before, after } = {}) {
  const params = new URLSearchParams();
  if (limit !== undefined && limit !== null && limit !== "") {
    params.set("limit", String(limit));
  }
  if (before) {
    params.set("before", String(before));
  }
  if (after) {
    params.set("after", String(after));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function outputPageQuery({ after, agentId, stream, limit, maxBytes } = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of [["after", after], ["agent_id", agentId], ["stream", stream], ["limit", limit], ["max_bytes", maxBytes]]) {
    if (value !== undefined && value !== null) params.set(String(key), String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function metadataPageQuery({ limit, after } = {}) {
  const params = new URLSearchParams();
  for (const [key,value] of [["limit",limit],["after",after]]) {
    if (value !== undefined && value !== null) params.set(String(key),String(value));
  }
  const query=params.toString();
  return query ? `?${query}` : "";
}

function remediationQuery({ agentId, policyId, limit } = {}) {
  const params = new URLSearchParams();
  if (agentId) {
    params.set("agent_id", String(agentId));
  }
  if (policyId) {
    params.set("policy_id", String(policyId));
  }
  if (limit !== undefined && limit !== null && limit !== "") {
    params.set("limit", String(limit));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function defaultFormatApiError(path, status) {
  if (status === 401) return "Your login expired or was revoked. Sign in again.";
  if (status === 403) return "Your account does not have permission for this action.";
  return `${path} returned ${status}`;
}

export function normalizeAdminToken(value) {
  let token = String(value ?? "").trim();
  if (token.toLowerCase().startsWith("bearer ")) {
    token = token.slice("bearer ".length).trim();
  }
  return token;
}

/** Creates the HTTP effect boundary; tokens are read for each request and never persisted. */
export function createApiClient({ fetchImpl = globalThis.fetch, tokenProvider = () => "", formatError = defaultFormatApiError, onUnauthorized = () => {} } = {}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is required.");
  }

  let generation = 0;
  /** @type {{mode: "legacy"|"cookie"|"anonymous", csrfToken?:string}|null} */
  let authentication = null;
  let lifetime = new AbortController();

  /**
   * Retires all prior effects; never submits or retries a request.
   * @param {{mode:"legacy"|"cookie"|"anonymous",csrfToken?:string}} context
   */
  function setAuthentication({ mode, csrfToken = "" }) {
    if (!["legacy", "cookie", "anonymous"].includes(mode)) throw new Error("Invalid authentication mode.");
    lifetime.abort(new DOMException("Authentication changed.", "AbortError"));
    generation += 1;
    lifetime = new AbortController();
    authentication = { mode, csrfToken: mode === "cookie" ? String(csrfToken) : "" };
    return generation;
  }

  /** @param {string} path @param {RequestInit} options @param {boolean} missingIsError @param {string} errorPath Safe diagnostic route. @param {boolean} useBearer Whether this effect uses the business credential boundary. */
  async function request(path, options = {}, missingIsError = false, errorPath = path, useBearer = true) {
    options.signal?.throwIfAborted();
    const selectedGeneration = generation;
    const mode = authentication?.mode || "legacy";
    const signal = authentication
      ? AbortSignal.any([lifetime.signal, ...(options.signal ? [options.signal] : [])])
      : options.signal;
    const current = () => {
      signal?.throwIfAborted();
      if (selectedGeneration !== generation) throw new DOMException("Authentication changed.", "AbortError");
    };
    const token = useBearer && mode === "legacy" ? normalizeAdminToken(tokenProvider()) : "";
    const mutation = options.method && !["GET", "HEAD"].includes(options.method);
    const csrfToken = mode === "cookie" && mutation ? authentication?.csrfToken : "";
    let response;
    try {
      response = await fetchImpl(path, {
        ...options,
        ...(signal ? { signal } : {}),
        credentials: useBearer && mode === "legacy" ? "omit" : "same-origin",
        cache: "no-store",
        headers: {
          ...(token ? { Authorization: "Bearer " + token } : {}),
          Accept: "application/json",
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}),
          ...(options.headers || {}),
        },
      });
    } catch (error) { current(); throw error; }
    current();
    if (response.status === 404 && !missingIsError) return null;
    if (!response.ok) {
      const rejection = path === "/api/jobs/catalog-runbook" && options.method === "POST" && response.status === 409
        ? response.headers?.get("Fleet-Catalog-Rejection") : null;
      const catalogRejected = typeof rejection === "string" && ["catalog_selection_changed", "catalog_target_unavailable", "catalog_target_unsupported", "catalog_target_capabilities_stale"].includes(rejection);
      const error = new ApiHttpError(formatError(errorPath, response.status), response.status, catalogRejected);
      if (response.status === 401 && authentication && authentication.mode !== "anonymous" && !["/api/auth/status", "/api/auth/login", "/api/auth/setup"].includes(path)) {
        setAuthentication({ mode: "anonymous" });
        // Notification cannot replace the actual HTTP failure.
        try { onUnauthorized(); } catch {}
      }
      throw error;
    }
    if (response.status === 204) return null;
    let body;
    try { body = await response.json(); } catch (error) { current(); throw error; }
    current();
    return body;
  }

  function authRequest(path, options = {}, errorPath = path) {
    return request(path, { credentials: "same-origin", cache: "no-store", ...options }, true, errorPath, false);
  }

  return {
    setAuthentication,
    getAuthGeneration: () => generation,
    getAdminPersonalTokens({ limit, after, signal } = {}) {
      return authRequest(`/api/auth/tokens${metadataPageQuery({ limit, after })}`, signal ? { signal } : {}, "/api/auth/tokens");
    },
    revokeAdminPersonalToken(tokenId, { csrfToken, signal } = {}) {
      return authRequest(`/api/auth/tokens/${encodePathValue(tokenId)}`, { method: "DELETE", headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) }, "/api/auth/tokens/{token_id}");
    },
    changeOwnAdminPassword(body, { csrfToken, signal } = {}) {
      return authRequest("/api/auth/password", { method: "POST", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) });
    },
    createAdminPersonalToken(body, { csrfToken, signal } = {}) {
      return authRequest("/api/auth/tokens", { method: "POST", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) });
    },
    createAdminUser(body, { csrfToken, signal } = {}) {
      return authRequest("/api/admin/users", { method: "POST", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) });
    },
    changeAdminUser(userId, body, { csrfToken, signal } = {}) {
      return authRequest(`/api/admin/users/${encodePathValue(userId)}`, { method: "PATCH", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) }, "/api/admin/users/{user_id}");
    },
    resetAdminUserPassword(userId, body, { csrfToken, signal } = {}) {
      return authRequest(`/api/admin/users/${encodePathValue(userId)}/password-reset`, { method: "POST", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) }, "/api/admin/users/{user_id}/password-reset");
    },
    getAdminUsers({ limit, after, signal } = {}) {
      return authRequest(`/api/admin/users${metadataPageQuery({limit,after})}`,signal ? {signal} : {},"/api/admin/users");
    },
    getAdminUser(userId, { signal } = {}) {
      return authRequest(`/api/admin/users/${encodePathValue(userId)}`,signal ? {signal} : {},"/api/admin/users/{user_id}");
    },
    getAuthStatus({ signal } = {}) {
      return authRequest("/api/auth/status", signal ? { signal } : {});
    },
    loginAdmin(body, { signal } = {}) {
      return authRequest("/api/auth/login", { method: "POST", body: JSON.stringify(body), ...(signal ? { signal } : {}) });
    },
    getAdminSession({ signal } = {}) {
      return authRequest("/api/auth/session", signal ? { signal } : {});
    },
    async logoutAdmin(body = {}, { csrfToken, signal } = {}) {
      const result = await authRequest("/api/auth/logout", { method: "POST", body: JSON.stringify(body), headers: csrfToken ? { "X-Fleet-CSRF": csrfToken } : {}, ...(signal ? { signal } : {}) });
      if (authentication) setAuthentication({ mode: "anonymous" });
      return result;
    },
    completeAdminSetup(body, { signal } = {}) {
      return authRequest("/api/auth/setup", { method: "POST", body: JSON.stringify(body), ...(signal ? { signal } : {}) });
    },
    /** Creates one Job from a durable catalog reference; callers reconcile an uncertain result by the same Job ID. */
    createCatalogRunbookJob(body, { signal } = {}) {
      return request("/api/jobs/catalog-runbook", { method: "POST", body: JSON.stringify(body), ...(signal ? { signal } : {}) }, true);
    },
    listAgents() {
      return request("/api/agents");
    },
    getLatestFacts(agentId) {
      return request(`/api/agents/${encodePathValue(agentId)}/facts/latest`);
    },
    listFacts(agentId, page = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/facts${pageQuery(page)}`);
    },
    getLatestMetrics(agentId) {
      return request(`/api/agents/${encodePathValue(agentId)}/metrics/latest`);
    },
    listMetrics(agentId, page = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/metrics${pageQuery(page)}`);
    },
    listAgentLogs(agentId, page = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/logs${pageQuery(page)}`);
    },
    getLatestDrift(agentId) {
      return request(`/api/agents/${encodePathValue(agentId)}/drift/latest`);
    },
    listDrift(agentId, page = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/drift${pageQuery(page)}`);
    },
    revokeAgentKey(agentId, body = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/revoke-key`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    getAgentCertificateLifecycleStatus(agentId) {
      return request(`/api/agents/${encodePathValue(agentId)}/certificate-lifecycle/status`);
    },
    requestAgentCertificateIssuance(agentId, body = {}) {
      return request(`/api/agents/${encodePathValue(agentId)}/certificate-lifecycle/request-issuance`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    getControllerSigningRotationStatus() {
      return request("/api/controller/signing-rotation/status");
    },
    stageControllerSigningTrustBundle(body = {}) {
      return request("/api/controller/signing-rotation/rollout-trust-bundle/staged", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    listJobs({ signal } = {}) {
      return request("/api/jobs", { signal });
    },
    listApprovals(status = "", { signal } = {}) {
      const query = status ? `?status=${encodeURIComponent(status)}` : "";
      return request(`/api/approvals${query}`, { signal });
    },
    listPolicies() {
      return request("/api/policies");
    },
    listCatalogSources({ signal, ...page } = {}) {
      const path = "/api/catalog/sources";
      return request(`${path}${pageQuery(page)}`, { signal }, true, path);
    },
    registerCatalogSource(body = {}, { signal } = {}) { return request("/api/catalog/sources", { method: "POST", body: JSON.stringify(body), signal }); },
    startCatalogSync(sourceId, body = {}, { signal } = {}) { return request(`/api/catalog/sources/${encodePathValue(sourceId)}/sync`, { method: "POST", body: JSON.stringify(body), signal }); },
    getCatalogSyncOperation(sourceId, operationId, { signal } = {}) {
      const path = `/api/catalog/sources/${encodePathValue(sourceId)}/sync-operations/${encodePathValue(operationId)}`;
      return request(path, { signal }, true, path);
    },
    activateCatalogRevision(sourceId, body = {}, { signal } = {}) { return request(`/api/catalog/sources/${encodePathValue(sourceId)}/activate`, { method: "POST", body: JSON.stringify(body), signal }); },
    listCatalogRevisions(sourceId, { signal, ...page } = {}) {
      const path = `/api/catalog/sources/${encodePathValue(sourceId)}/revisions`;
      return request(`${path}${pageQuery(page)}`, { signal }, true, path);
    },
    listCatalogDocuments(sourceId, commit, { signal, ...page } = {}) {
      const path = `/api/catalog/sources/${encodePathValue(sourceId)}/revisions/${encodePathValue(commit)}/documents`;
      return request(`${path}${pageQuery(page)}`, { signal }, true, path);
    },
    getCatalogDocumentDetail(sourceId, commit, path, { signal } = {}) {
      const route = `/api/catalog/sources/${encodePathValue(sourceId)}/revisions/${encodePathValue(commit)}/document`;
      return request(`${route}?path=${encodeURIComponent(path)}`, { signal }, true, route);
    },
    savePolicy(body = {}) {
      return request("/api/policies", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    assignPolicy(policyId, body = {}) {
      return request(`/api/policies/${encodePathValue(policyId)}/assignments`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    schedulePolicyDrift(policyId, body = {}) {
      return request(`/api/policies/${encodePathValue(policyId)}/schedules`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    listAgentPolicies(agentId) {
      return request(`/api/agents/${encodePathValue(agentId)}/policies`);
    },
    listDueScheduledDrift() {
      return request("/api/drift/scheduled");
    },
    approveApproval(approvalId, body = {}) {
      return request(`/api/approvals/${encodePathValue(approvalId)}/approve`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    rejectApproval(approvalId, body = {}) {
      return request(`/api/approvals/${encodePathValue(approvalId)}/reject`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    expireApprovals(body = {}) {
      return request("/api/approvals/expire", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    listRemediations(filters = {}) {
      return request(`/api/remediations${remediationQuery(filters)}`);
    },
    getRemediation(remediationId) {
      return request(`/api/remediations/${encodePathValue(remediationId)}`);
    },
    createRemediationApprovalRequest(remediationId, body = {}) {
      return request(`/api/remediations/${encodePathValue(remediationId)}/approval-request`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    approveRemediationJob(remediationId, body = {}) {
      return request(`/api/remediations/${encodePathValue(remediationId)}/approve`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    markRemediationRunning(remediationId, body = {}) {
      return request(`/api/remediations/${encodePathValue(remediationId)}/running`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    recordRemediationResult(remediationId, body = {}) {
      return request(`/api/remediations/${encodePathValue(remediationId)}/result`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    verifyRemediation(remediationId, body = {}) {
      return request(`/api/remediations/${encodePathValue(remediationId)}/verify`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    previewSelector(body, { signal } = {}) {
      return request("/api/selectors/preview", {
        method: "POST",
        body: JSON.stringify(body),
        signal,
      }, true);
    },
    /**
     * Reads canonical Job state. Missing/forbidden Jobs fail rather than resembling empty success.
     * @param {string} jobId
     * @param {{signal?: AbortSignal}} options
     */
    getJob(jobId, { signal } = {}) {
      return request(`/api/jobs/${encodePathValue(jobId)}`, signal ? { signal } : {}, true);
    },
    /**
     * Reads output without interpreting its presence as task success; cancellation preserves its original reason.
     * @param {string} jobId
     * @param {{signal?: AbortSignal}} options
     */
    getJobOutput(jobId, { signal } = {}) {
      return request(`/api/jobs/${encodePathValue(jobId)}/output`, signal ? { signal } : {}, true);
    },
    /**
     * Reads stored fragments without converting decimal identifiers or persisting the cursor.
     * @param {string} jobId
     * @param {{after?: string, agentId?: string, stream?: string, limit?: number, maxBytes?: number, signal?: AbortSignal}} options
     */
    getJobOutputPage(jobId, { signal, ...page } = {}) {
      return request(`/api/jobs/${encodePathValue(jobId)}/output-page${outputPageQuery(page)}`, signal ? { signal } : {}, true,
        `/api/jobs/${encodePathValue(jobId)}/output-page`);
    },
    /** Reads a selected artifact with optional view-owner cancellation; missing data stays null. */
    getJobArtifact(jobId, artifactId, { signal } = {}) {
      return request(`/api/jobs/${encodePathValue(jobId)}/artifacts/${encodePathValue(artifactId)}`, signal ? { signal } : {});
    },
    cancelJob(jobId, body = {}) {
      return request(`/api/jobs/${encodePathValue(jobId)}/cancel`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    listAudit() {
      return request("/api/audit");
    },
    exportAudit({ category = "", limit = 50, before = "" } = {}) {
      const query = new URLSearchParams();
      if (category) query.set("category", category);
      query.set("limit", String(limit));
      if (before) query.set("before", before);
      return request(`/api/audit/export?${query.toString()}`);
    },
    listEnrollmentTokens() {
      return request("/api/enrollment-tokens");
    },
    createEnrollmentToken(body) {
      return request("/api/enrollment-tokens", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    revokeEnrollmentToken(id) {
      return request(`/api/enrollment-tokens/${encodePathValue(id)}`, {
        method: "DELETE",
      });
    },
    createCommandJob(body, { signal } = {}) {
      return request("/api/jobs/command", {
        method: "POST",
        body: JSON.stringify(body),
        ...(signal ? { signal } : {}),
      });
    },
    createDriftCheckJob(body) {
      return request("/api/jobs/drift-check", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    createRunbookJob(body, { signal } = {}) {
      return request("/api/jobs/runbook", {
        method: "POST",
        body: JSON.stringify(body),
        ...(signal ? { signal } : {}),
      });
    },
  };
}
