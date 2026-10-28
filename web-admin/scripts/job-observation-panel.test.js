/** @file UI effects for the real observation composition; fake DOM/clock, no network. */
import assert from "node:assert/strict";
import test from "node:test";
import * as app from "../app.js";
import { ApiHttpError } from "../api-client.js";
import { createJobOutputReader } from "../job-output-reader.js";

async function settle() {
  for (let i = 0; i < 24; i += 1) await Promise.resolve();
}

class FakeClock {
  time = 10000;
  nextId = 1;
  timers = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => {
    const id = this.nextId++;
    this.timers.set(id, { at: this.time + delay, callback });
    return id;
  };
  clearTimeout = (id) => this.timers.delete(id);
  async advance(ms) {
    const end = this.time + ms;
    for (let i = 0; i < 1000; i += 1) {
      const next = [...this.timers.entries()].filter(([, t]) => t.at <= end)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      assert(i < 999, "unbounded timer loop");
      this.time = next[1].at;
      this.timers.delete(next[0]);
      next[1].callback();
      await settle();
    }
    this.time = end;
    await settle();
  }
}

class ElementDouble extends EventTarget {
  constructor(ownerDocument) {
    super();
    this.ownerDocument = ownerDocument;
  }
  _text = "";
  innerHTML = "";
  disabled = false;
  hidden = false;
  dataset = {};
  scrollTop = 0;
  scrollLeft = 0;
  focusCalls = 0;
  writes = 0;
  get textContent() { return this._text; }
  set textContent(value) {
    this._text = value;
    this.writes += 1;
    this.scrollTop = 0;
    this.scrollLeft = 0;
  }
  focus(options) {
    this.focusCalls += 1;
    this.lastFocusOptions = options;
    this.ownerDocument.activeElement = this;
  }
  click() { if (!this.disabled) this.dispatchEvent(new Event("click")); }
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness({ getJob = async (id) => ({ id, status: "running", dispatch_state: "running" }), getJobOutput = async () => [], getJobArtifact = async () => null,
  pageMode = false, getJobOutputPage = async () => { throw new Error("page fixture missing"); } } = {}) {
  const document = { activeElement: null };
  const elements = Object.fromEntries(["status", "lastUpdated", "pause", "resume", "output", "targets", "artifacts", "history", "nextPage", "outputInfo"]
    .map((key) => [key, new ElementDouble(document)]));
  const clock = new FakeClock();
  const reads = [];
  assert.equal(typeof app.createJobObservationPanel, "function", "app must compose the existing observer into its real result panel");
  const apiClient = {
      getJob: (id, options) => { reads.push({ id, signal: options.signal }); return getJob(id, options); },
      getJobOutput,
      getJobOutputPage,
      getJobArtifact,
  };
  const panel = app.createJobObservationPanel({
    elements, clock, apiClient,
    outputReaderFactory: pageMode ? () => createJobOutputReader({ api: apiClient }) : undefined,
  });
  panel.setContext({ route: "run", authenticated: true });
  return { panel, elements, clock, reads, document };
}

function page(items = [], { cursor = "op1.end", more = false, caught = !more, history = "tracked", status = "running" } = {}) {
  return { items, next_after: cursor, has_more: more, caught_up: caught, history, job_status: status };
}
function fragment(key, data, sequence = String(Number(key) - 1)) {
  return { chunk_key: key, agent_id: "agent-a", stream: "stdout", sequence, offset_bytes: "0",
    total_bytes: String(new TextEncoder().encode(data).length), data, chunk_complete: true };
}

test("production page composition renders canonical results and output with no legacy fetch", async () => {
  let legacy = 0;
  const responses = [page([fragment("1", "visible output")], { status: "partial_success" }), page([], { status: "partial_success" })];
  const h = harness({ pageMode: true,
    getJob: async (id) => ({ id, status: "partial_success", target_agents: [{ agent_id: "a", assignment_status: "succeeded" }, { agent_id: "b", assignment_status: "failed", last_error: "exit 7" }] }),
    getJobOutputPage: async () => responses.shift(),
    getJobOutput: async () => { legacy += 1; return []; },
  });
  h.panel.select("paged"); await settle();
  assert.match(h.elements.output.textContent, /visible output/);
  assert.equal(h.panel.getSnapshot().phase, "following");
  await h.clock.advance(0);
  assert.equal(h.panel.getSnapshot().phase, "completed");
  assert.match(h.elements.targets.innerHTML, /succeeded/); assert.match(h.elements.targets.innerHTML, /exit 7/);
  assert.equal(legacy, 0); assert.equal(h.elements.history.disabled, false);
  h.panel.dispose();
});

test("unknown and pruned empty pages never resemble completed-with-no-output capture", async () => {
  for (const history of ["unknown", "pruned"]) {
    const h = harness({ pageMode: true, getJob: async (id) => ({ id, status: "success" }),
      getJobOutputPage: async () => page([], { history, status: "success" }) });
    h.panel.select("empty"); await settle(); await h.clock.advance(0);
    assert.equal(h.panel.getSnapshot().phase, "completed");
    assert.match(h.elements.output.textContent, /unknown|removed/);
    assert.doesNotMatch(h.elements.output.textContent, /Completed with no output/);
    h.panel.dispose();
  }
});

test("browse history pauses live ownership, reads one page at a time and resumes a fresh live context", async () => {
  const calls = []; let history = false;
  const h = harness({ pageMode: true, getJobOutputPage: async (_id, options) => {
    calls.push(options.after);
    if (!history) return page([fragment("1", "live")]);
    if (!options.after) return page([fragment("1", "older history")], { cursor: "op1.first", more: true });
    return page([fragment("2", "next history")], { cursor: "op1.last" });
  } });
  h.panel.select("history-job"); await settle();
  history = true; h.elements.history.click(); await settle();
  assert.equal(h.panel.getSnapshot().phase, "history");
  assert.match(h.elements.output.textContent, /older history/); assert.equal(h.elements.nextPage.disabled, false);
  assert.equal(h.clock.timers.size, 0);
  const before = calls.length; await h.clock.advance(5000); assert.equal(calls.length, before);
  h.elements.nextPage.focus(); h.elements.nextPage.click(); await settle();
  assert.match(h.elements.output.textContent, /next history/); assert.doesNotMatch(h.elements.output.textContent, /older history/);
  assert.equal(h.elements.nextPage.disabled, true); assert.equal(h.document.activeElement, h.elements.resume);
  history = false; h.elements.resume.click(); await settle();
  assert.equal(h.panel.getSnapshot().phase, "following");
  assert.equal(calls.at(-1), undefined); assert.match(h.elements.output.textContent, /live/);
  h.panel.dispose();
});

test("keyboard focus stays on next page through a pending read when more history remains", async () => {
  const wait = deferred(); let history = false, historyReads = 0;
  const h = harness({ pageMode: true, getJobOutputPage: async () => {
    if (!history) return page([]);
    historyReads += 1;
    return historyReads === 1 ? page([fragment("1", "first")], { cursor: "op1.first", more: true }) : wait.promise;
  } });
  h.panel.select("keyboard-history"); await settle();
  history = true; h.elements.history.click(); await settle();
  h.elements.nextPage.focus(); h.elements.nextPage.click(); await settle();
  assert.equal(h.document.activeElement, h.elements.nextPage, "busy navigation must preserve keyboard focus");
  h.elements.nextPage.click(); await settle();
  assert.equal(historyReads, 2, "repeat activation must not create another in-flight read");
  wait.resolve(page([fragment("2", "second")], { cursor: "op1.second", more: true })); await settle();
  assert.equal(h.document.activeElement, h.elements.nextPage);
  assert.equal(h.elements.nextPage.disabled, false);
  assert.match(h.elements.output.textContent, /second/);
  h.panel.dispose();
});

test("history loading is canceled on selection, route, auth and artifact changes", async () => {
  for (const action of ["selection", "route", "auth", "artifact"]) {
    let loading = false; const wait = deferred(); let signal;
    const h = harness({ pageMode: true,
      getJobOutputPage: async (_id, options) => {
        if (loading) { signal = options.signal; return wait.promise; }
        return page([fragment("1", "live")]);
      }, getJobArtifact: async () => ({ content_bytes: [65] }),
    });
    h.panel.select("first"); await settle(); loading = true;
    h.elements.history.click(); await settle(); assert(signal);
    if (action === "selection") { loading = false; h.panel.select("second"); }
    if (action === "route") h.panel.setContext({ route: "agents", authenticated: true });
    if (action === "auth") h.panel.setContext({ route: "run", authenticated: false });
    if (action === "artifact") void h.panel.showArtifact("first", "artifact");
    await settle(); assert.equal(signal.aborted, true, action);
    const text = h.elements.output.textContent;
    wait.resolve(page([fragment("1", "retired history")])); await settle();
    assert.equal(h.elements.output.textContent, text, action);
    h.panel.dispose(); assert.equal(h.clock.timers.size, 0);
  }
});

test("history failures retry finitely, stale cursors stop and explicit reopen discards old context", async () => {
  let loading = false, reads = 0, stale = false;
  const h = harness({ pageMode: true, getJobOutputPage: async () => {
    if (!loading) return page([fragment("1", "live")]);
    reads += 1; throw new ApiHttpError("safe", stale ? 409 : 500);
  } });
  h.panel.select("job"); await settle(); loading = true; h.elements.history.click(); await settle();
  assert.equal(h.panel.getSnapshot().phase, "error");
  await h.clock.advance(1000); await h.clock.advance(2000); await h.clock.advance(4000);
  assert.equal(reads, 4); assert.equal(h.clock.timers.size, 0);
  stale = true; h.elements.history.click(); await settle();
  assert.equal(h.panel.getSnapshot().error.kind, "output_stale"); assert.equal(h.elements.nextPage.disabled, true);
  assert.match(h.elements.status.textContent, /reopen|Reopen|changed/);
  loading = false; h.elements.history.click(); await settle();
  assert.equal(h.panel.getSnapshot().phase, "history"); assert.match(h.elements.output.textContent, /live/);
  h.panel.dispose();
});

test("history deadline can retry before an uncooperative previous page promise settles", async () => {
  let history = false, calls = 0; const wait = deferred();
  const h = harness({ pageMode: true, getJobOutputPage: async () => {
    if (!history) return page();
    calls += 1; return calls === 1 ? wait.promise : page([fragment("1", "recovered")]);
  } });
  h.panel.select("job"); await settle(); history = true; h.elements.history.click(); await settle();
  await h.clock.advance(10000);
  assert.equal(h.panel.getSnapshot().error.kind, "timeout");
  try {
    await h.clock.advance(1000);
    assert.equal(h.panel.getSnapshot().phase, "history"); assert.match(h.elements.output.textContent, /recovered/);
  } finally { wait.resolve(page([fragment("1", "retired")])); await settle(); h.panel.dispose(); }
});

test("live page updates preserve reading scroll and focus, while trimmed output is explicitly limited", async () => {
  let count = 0;
  const h = harness({ pageMode: true, getJobOutputPage: async () => {
    count += 1;
    return page([fragment(String(count), `part ${count}\n`)], { cursor: `op1.c${count}` });
  } });
  h.panel.select("job"); await settle();
  h.elements.output.scrollTop = 53; h.elements.output.scrollLeft = 17; h.elements.output.focus();
  const focused = h.document.activeElement;
  await h.clock.advance(1000);
  assert.equal(h.elements.output.scrollTop, 53); assert.equal(h.elements.output.scrollLeft, 17);
  assert.equal(h.document.activeElement, focused); assert.match(h.elements.output.textContent, /part 2/);
  h.panel.dispose();
  let n = 0;
  const large = harness({ pageMode: true, getJobOutputPage: async () => {
    n += 1; return page([fragment(String(n), "x".repeat(64000))], { cursor: `op1.c${n}`, more: n < 20 });
  } });
  large.panel.select("large"); await settle(); await large.clock.advance(0);
  assert.equal(n, 20); assert.equal(large.panel.getSnapshot().output.trimmed, true);
  assert.match(large.elements.outputInfo.textContent, /limited|outside this view/);
  assert(new TextEncoder().encode(large.elements.output.textContent).length <= 1024 * 1024);
  large.panel.dispose();
});

test("history view errors stop reads rather than being retried as network failures", async () => {
  let reading = false, calls = 0;
  const h = harness({ pageMode: true, getJobOutputPage: async () => {
    calls += 1; return page([fragment("1", reading ? "history" : "live")]);
  } });
  h.panel.select("job"); await settle(); reading = true;
  Object.defineProperty(h.elements.output, "textContent", { get: () => "prior", set: () => { throw new TypeError("private DOM detail"); } });
  h.elements.history.click(); await settle();
  assert.equal(h.panel.getSnapshot().error.kind, "view");
  const before = calls; await h.clock.advance(60000);
  assert.equal(calls, before); assert.equal(h.clock.timers.size, 0);
  assert(!JSON.stringify(h.panel.getSnapshot()).includes("private DOM detail"));
  h.panel.dispose();
});

test("the visible panel follows beyond 45 reads through canonical terminal and final output", async () => {
  let count = 0;
  const h = harness({ getJob: async (id) => ({ id, status: ++count > 46 ? "success" : "running" }) });
  h.panel.select("long-job");
  await settle();
  await h.clock.advance(45000);
  assert.equal(count, 46);
  assert.match(h.elements.status.textContent, /Following/);
  assert.match(h.elements.lastUpdated.textContent, /Last successful update:/);
  await h.clock.advance(1000);
  assert.equal(h.panel.getSnapshot().phase, "completed");
  assert.match(h.elements.output.textContent, /Status: success/);
  assert.match(h.elements.output.textContent, /Completed with no output/);
  assert.equal(h.clock.timers.size, 0);
  await h.clock.advance(60000);
  assert.equal(count, 47);
  h.panel.dispose();
});

test("partial success is a canonical terminal result in either Job response field", () => {
  for (const job of [
    { status: "partial_success" },
    { dispatch_state: "partial_success" },
    { status: "partial_success", dispatch_state: "partial_success" },
  ]) {
    assert.equal(app.isTerminalJob(job), true);
    assert.match(app.jobStatusMessage(job), /Completed with mixed results/);
  }
});

test("partial success preserves per-agent results and stops after its final output read", async () => {
  const output = deferred();
  const h = harness({
    getJob: async (id) => ({
      id, status: "partial_success", dispatch_state: "partial_success",
      target_agents: [
        { agent_id: "A", assignment_status: "succeeded", last_error: "" },
        { agent_id: "B", assignment_status: "failed", last_error: "exit_code=7" },
      ],
    }),
    getJobOutput: () => output.promise,
  });
  h.panel.select("mixed");
  await settle();
  assert.notEqual(h.panel.getSnapshot().phase, "completed", "wait for the final stored output");
  output.resolve([{ agent_id: "B", stream: "stderr", sequence: 0, data: "test failure" }]);
  await settle();
  assert.equal(h.panel.getSnapshot().phase, "completed");
  assert.match(h.elements.status.textContent, /Server result: partial_success/);
  assert.match(h.elements.targets.innerHTML, /succeeded/);
  assert.match(h.elements.targets.innerHTML, /failed/);
  assert.match(h.elements.targets.innerHTML, /exit_code=7/);
  assert.match(h.elements.output.textContent, /test failure/);
  assert.equal(h.clock.timers.size, 0);
  const reads = h.reads.length;
  await h.clock.advance(60000);
  assert.equal(h.reads.length, reads, "terminal result must stop polling");
  h.panel.dispose();
});

for (const stage of ["job", "output"]) {
  for (const outcome of ["success", "failure"]) {
    test(`panel A→B protects DOM from late A ${stage} ${outcome}`, async () => {
      const late = deferred();
      const h = harness({
        getJob: (id) => id === "A" && stage === "job" ? late.promise : Promise.resolve({ id, status: "running", target_agents: [{ agent_id: id, assignment_status: "started" }] }),
        getJobOutput: (id) => id === "A" ? late.promise : Promise.resolve([{ agent_id: id, stream: "stdout", data: `${id} output` }]),
      });
      h.panel.select("A");
      await settle();
      h.panel.select("B");
      await settle();
      const before = Object.values(h.elements).map((e) => [e.textContent, e.innerHTML]);
      assert(h.reads[0].signal.aborted);
      if (outcome === "failure") late.reject(new TypeError("private stale failure"));
      else late.resolve(stage === "job" ? { id: "A", status: "failed" } : [{ data: "A stale output" }]);
      await settle();
      assert.deepEqual(Object.values(h.elements).map((e) => [e.textContent, e.innerHTML]), before);
      assert.match(h.elements.output.textContent, /B output/);
      assert.match(h.elements.targets.innerHTML, />B</);
      h.panel.dispose();
    });
  }
}

test("pause/resume controls cancel the read and leave canonical state untouched", async () => {
  const pending = deferred();
  let count = 0;
  const h = harness({ getJob: (id) => ++count === 1 ? pending.promise : Promise.resolve({ id, status: "running" }) });
  h.panel.select("one");
  h.elements.pause.click();
  assert(h.reads[0].signal.aborted);
  assert.equal(h.clock.timers.size, 0);
  assert.match(h.elements.status.textContent, /paused/i);
  assert.match(h.elements.lastUpdated.textContent, /Not yet/);
  await h.clock.advance(60000);
  assert.equal(count, 1);
  h.elements.resume.click();
  await settle();
  assert.equal(count, 2);
  assert.equal(h.panel.getSnapshot().job.status, "running");
  pending.resolve({ id: "one", status: "failed" });
  await settle();
  assert.equal(h.panel.getSnapshot().job.status, "running");
  h.panel.dispose();
});

test("a focused observation control hands focus to its enabled counterpart without scrolling", async () => {
  let terminal = false;
  const h = harness({ getJob: async (id) => ({ id, status: terminal ? "success" : "running" }) });
  h.panel.select("keyboard-job");
  await settle();
  h.elements.pause.focus();
  h.elements.pause.click();
  assert.equal(h.document.activeElement, h.elements.resume);
  assert.deepEqual(h.elements.resume.lastFocusOptions, { preventScroll: true });
  h.elements.resume.click();
  assert.equal(h.document.activeElement, h.elements.pause);
  assert.deepEqual(h.elements.pause.lastFocusOptions, { preventScroll: true });
  await settle();
  terminal = true;
  await h.clock.advance(1000);
  assert.equal(h.document.activeElement, h.elements.resume, "terminal update must not drop focus on its disabled Pause button");
  h.panel.dispose();
});

test("periodic and terminal renders never move focus away from output reading", async () => {
  let terminal = false;
  const h = harness({ getJob: async (id) => ({ id, status: terminal ? "success" : "running" }) });
  h.panel.select("reading-job");
  await settle();
  h.elements.output.focus();
  await h.clock.advance(1000);
  terminal = true;
  await h.clock.advance(1000);
  assert.equal(h.document.activeElement, h.elements.output);
  assert.equal(h.elements.pause.focusCalls, 0);
  assert.equal(h.elements.resume.focusCalls, 0);
  h.panel.dispose();
});

test("leaving either workspace aborts; returning or switching Run/Runbooks reads the same Job afresh", async () => {
  const pending = deferred();
  let count = 0;
  const h = harness({ getJob: (id) => ++count === 1 ? pending.promise : Promise.resolve({ id, status: "canceled" }) });
  h.panel.select("same");
  const selection = h.panel.captureSelection();
  h.panel.setContext({ route: "agents", authenticated: true });
  assert(h.reads[0].signal.aborted);
  assert(!h.panel.isCurrentSelection(selection));
  assert.equal(h.clock.timers.size, 0);
  pending.resolve({ id: "same", status: "success" });
  await settle();
  h.panel.setContext({ route: "runbooks", authenticated: true });
  await settle();
  assert.equal(count, 2);
  assert.match(h.elements.output.textContent, /Status: canceled/);
  h.panel.setContext({ route: "run", authenticated: true });
  await settle();
  assert.equal(count, 3);
  h.panel.setContext({ route: "run", authenticated: true });
  await settle();
  assert.equal(count, 3, "unchanged context must not spawn another owner");
  h.panel.dispose();
});

test("logout clears the selection and result; late reads cannot repopulate private output", async () => {
  const pending = deferred();
  const h = harness({ getJobOutput: () => pending.promise });
  h.panel.select("private-job");
  await settle();
  h.panel.setContext({ route: "run", authenticated: false });
  assert(h.reads[0].signal.aborted);
  assert.equal(h.panel.getJobId(), "");
  assert.equal(h.clock.timers.size, 0);
  const cleared = h.elements.output.textContent;
  pending.resolve([{ data: "private old principal output" }]);
  await settle();
  assert.equal(h.elements.output.textContent, cleared);
  assert(!h.elements.output.textContent.includes("private-job"));
  h.panel.setContext({ route: "runbooks", authenticated: true });
  await settle();
  assert.equal(h.reads.length, 1, "reauthentication must not recover the previous principal's selection");
  h.panel.dispose();
});

for (const [status, message] of [[401, /authenticate/i], [403, /permission/i], [404, /not found/i]]) {
  test(`HTTP ${status} is visible without empty-success fallback or automatic retries`, async () => {
    const h = harness({ getJob: async () => { throw new ApiHttpError("private response body", status); } });
    h.panel.select("one");
    await settle();
    assert.match(h.elements.status.textContent, message);
    assert(!h.elements.status.textContent.includes("private response body"));
    assert(!h.elements.output.textContent.includes("Completed with no output"));
    assert.match(h.elements.lastUpdated.textContent, /Not yet/);
    await h.clock.advance(60000);
    assert.equal(h.reads.length, 1);
    assert.equal(h.clock.timers.size, 0);
    assert.equal(h.elements.resume.disabled, false);
    h.panel.dispose();
  });
}

test("bounded failure keeps the last snapshot/time, exposes retry exhaustion, and permits explicit resume", async () => {
  let fail = false;
  const h = harness({ getJob: async (id) => {
    if (fail) throw new TypeError("private network details");
    return { id, status: "running" };
  } });
  h.panel.select("one");
  await settle();
  const updated = h.elements.lastUpdated.textContent;
  fail = true;
  await h.clock.advance(8000);
  assert.equal(h.reads.length, 5);
  assert.equal(h.clock.timers.size, 0);
  assert.equal(h.elements.lastUpdated.textContent, updated);
  assert.match(h.elements.status.textContent, /stopped/i);
  assert(!h.elements.status.textContent.includes("private network"));
  assert.equal(h.panel.getSnapshot().job.status, "running");
  fail = false;
  h.elements.resume.click();
  await settle();
  assert.match(h.elements.status.textContent, /Following/);
  h.panel.dispose();
});

for (const status of ["pending_approval", "canceled", "expired", "failed"]) {
  test(`two-Agent ${status} keeps each Assignment's canonical status/reason with empty output`, async () => {
    const h = harness({ getJob: async (id) => ({
      id, status, dispatch_state: status === "pending_approval" ? "created" : status,
      target_agents: [{ agent_id: "agent-a", assignment_status: "succeeded", last_error: "" },
        { agent_id: "agent-b", assignment_status: status === "pending_approval" ? "queued" : status, last_error: "execution_outcome_unknown" }],
    }) });
    h.panel.select("two-agent-job");
    await settle();
    assert.match(h.elements.targets.innerHTML, /agent-a/);
    assert.match(h.elements.targets.innerHTML, /succeeded/);
    assert.match(h.elements.targets.innerHTML, /agent-b/);
    assert.match(h.elements.targets.innerHTML, /execution_outcome_unknown/);
    assert.match(h.elements.output.textContent, new RegExp(`Status: ${status}`));
    assert(!h.elements.output.textContent.includes("Completed with no output"));
    if (status === "pending_approval") assert.match(h.elements.status.textContent, /Following/);
    else assert.equal(h.clock.timers.size, 0);
    h.panel.dispose();
  });
}

test("same-ID reselection invalidates view tokens and periodic output updates preserve scroll/focus", async () => {
  let output = "first output";
  const h = harness({ getJobOutput: async () => [{ agent_id: "agent-a", stream: "stderr", data: output }] });
  h.panel.select("one");
  await settle();
  const old = h.panel.captureSelection();
  h.elements.output.scrollTop = 53;
  h.elements.output.scrollLeft = 17;
  output = "first output\nmore output";
  await h.clock.advance(1000);
  assert.equal(h.elements.output.scrollTop, 53);
  assert.equal(h.elements.output.scrollLeft, 17);
  assert.equal(h.elements.output.focusCalls, 0);
  h.panel.select("one");
  assert(!h.panel.isCurrentSelection(old));
  await settle();
  h.panel.dispose();
  h.elements.resume.click();
  assert.equal(h.clock.timers.size, 0);
});

test("unknown execution outcome does not claim that the Agent process failed", () => {
  for (const reason of ["execution_outcome_unknown", "exit_code=-1,reason=execution_outcome_unknown"]) {
    const text = app.jobStatusMessage({ status: "failed", dispatch_state: "failed", last_error: reason });
    assert.match(text, /Execution outcome unknown/);
    assert(text.includes(reason));
    assert(!text.includes("Failed on agent"));
  }
});

for (const change of ["new-job", "same-job", "route", "logout", "resume"]) {
  test(`artifact reads are canceled on ${change} and cannot overwrite the selected Job`, async () => {
    const pending = deferred();
    let signal;
    const h = harness({ getJobArtifact: (_jobId, _artifactId, options) => {
      signal = options.signal;
      return pending.promise;
    } });
    h.panel.select("A");
    await settle();
    assert.equal(typeof h.panel.showArtifact, "function", "artifact effects need the same selected-view owner");
    const reading = h.panel.showArtifact("A", "artifact-A");
    await settle();
    if (change === "route") h.panel.setContext({ route: "agents", authenticated: true });
    else if (change === "logout") h.panel.setContext({ route: "run", authenticated: false });
    else if (change === "resume") h.panel.resume();
    else h.panel.select(change === "new-job" ? "B" : "A");
    await settle();
    assert(signal.aborted);
    const text = h.elements.output.textContent;
    pending.resolve({ artifact_id: "stale-artifact", body: "private stale body" });
    await reading;
    await settle();
    assert.equal(h.elements.output.textContent, text);
    assert(!text.includes("private stale body"));
    h.panel.dispose();
  });
}

test("an artifact read that ignores abort is bounded by a deadline and exposes no raw error", async () => {
  const h = harness({ getJobArtifact: () => new Promise(() => {}) });
  h.panel.select("A");
  await settle();
  assert.equal(typeof h.panel.showArtifact, "function");
  const reading = h.panel.showArtifact("A", "artifact-A");
  await h.clock.advance(10000);
  await reading;
  assert.match(h.elements.output.textContent, /timed out/i);
  assert.equal(h.clock.timers.size, 0);
  h.panel.dispose();
});

test("artifact preview pauses polling, preserves missing-body semantics, and resume restores Job output", async () => {
  let body = null;
  const h = harness({ getJobOutput: async () => [{ data: "canonical command output" }], getJobArtifact: async () => body });
  h.panel.select("A");
  await settle();
  await h.panel.showArtifact("A", "artifact-A");
  assert.match(h.elements.output.textContent, /missing or no longer available/);
  assert.equal(h.panel.getSnapshot().phase, "paused");
  assert.equal(h.clock.timers.size, 0);
  body = { artifact_id: "artifact-A", job_id: "A", content_bytes: [104, 101, 108, 108, 111] };
  await h.panel.showArtifact("A", "artifact-A");
  assert.match(h.elements.output.textContent, /Preview:\nhello/);
  h.panel.resume();
  await settle();
  assert.match(h.elements.output.textContent, /canonical command output/);
  h.panel.dispose();
});

test("artifact errors are safe and superseded artifact requests cannot replace the later preview", async () => {
  const older = deferred();
  let calls = 0;
  const h = harness({ getJobArtifact: async () => {
    calls += 1;
    if (calls === 1) return older.promise;
    if (calls === 2) return { artifact_id: "newer-preview", content_bytes: [111, 107] };
    throw new TypeError("private artifact error details");
  } });
  h.panel.select("A");
  await settle();
  const first = h.panel.showArtifact("A", "older");
  await h.panel.showArtifact("A", "newer");
  older.resolve({ artifact_id: "older-preview", content_bytes: [98, 97, 100] });
  await first;
  assert.match(h.elements.output.textContent, /newer-preview/);
  await h.panel.showArtifact("A", "error");
  assert.match(h.elements.output.textContent, /Could not load artifact/);
  assert(!h.elements.output.textContent.includes("private artifact error"));
  assert.equal(h.clock.timers.size, 0);
  h.panel.dispose();
});

test("same-route user changes clear selected output and cancel the previous observer",async()=>{
  const old=deferred();const h=harness({getJob:()=>old.promise});
  h.panel.setContext({route:"run",authenticated:true,authGeneration:1});
  h.panel.select("private-A");await settle();
  const signal=h.reads[0].signal;
  h.panel.setContext({route:"run",authenticated:true,authGeneration:2});
  old.resolve({id:"private-A",status:"running",dispatch_state:"running"});await settle();
  assert.equal(signal.aborted,true);
  assert.equal(h.panel.getJobId(),"");
  assert.equal(h.clock.timers.size,0);
  assert(!h.elements.output.textContent.includes("private-A"));
  h.panel.dispose();
});

test("direct Job submissions preserve uncertain IDs, cancel on identity change and never replay",async()=>{
  assert.equal(typeof app.createDirectJobSubmission,"function");
  const pending=deferred(), clock=new FakeClock();let posts=0,signal;
  const snapshots=[];
  const owner=app.createDirectJobSubmission({
    createJob:async(body,options)=>{posts++;signal=options.signal;return pending.promise;},
    getJob:async(id)=>({id,status:"queued"}),clock,onChange:value=>snapshots.push(value),
  });
  owner.setContext({authenticated:true,authGeneration:1});
  const sending=owner.submit({job_id:"uncertain-A",program:"private program",runbook_document:"private body"});
  await settle();
  owner.setContext({authenticated:true,authGeneration:2});
  pending.resolve({job_id:"uncertain-A",status:"queued"});await sending;await settle();
  assert.equal(signal.aborted,true);
  assert.equal(owner.getSnapshot().phase,"unknown");
  assert.equal(owner.getSnapshot().jobId,"uncertain-A");
  assert.equal(owner.getSnapshot().canSubmit,false);
  await owner.submit({job_id:"unintended-B"});
  assert.equal(posts,1);
  assert.equal((await owner.check()).id,"uncertain-A","new authority may explicitly read the stored Job");
  assert.equal(owner.getSnapshot().phase,"created");
  assert(!JSON.stringify(snapshots).includes("private"));
  assert.equal(clock.timers.size,0);owner.dispose();
});

test("direct Job timeout preserves its ID until a required read proves it missing",async()=>{
  assert.equal(typeof app.createDirectJobSubmission,"function");
  const clock=new FakeClock();let posts=0;
  const owner=app.createDirectJobSubmission({clock,
    createJob:()=>{posts++;return new Promise(()=>{});},getJob:async()=>{throw new ApiHttpError("missing",404);}});
  owner.setContext({authenticated:true,authGeneration:1});
  const sending=owner.submit({job_id:"timeout-A"});await settle();
  await clock.advance(10000);await sending;await settle();
  assert.equal(owner.getSnapshot().phase,"unknown");
  assert.equal(owner.getSnapshot().jobId,"timeout-A");
  await owner.check();
  assert.equal(owner.getSnapshot().phase,"missing");
  assert.equal(owner.getSnapshot().canSubmit,true,"only an explicit new submit is enabled after a required404");
  assert.equal(posts,1);assert.equal(clock.timers.size,0);owner.dispose();
});
