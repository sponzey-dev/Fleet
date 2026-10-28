/** @file Deterministic Job observation contracts; no live Controller, DOM or wall-clock waits. */
import assert from "node:assert/strict";
import test from "node:test";
import { createJobObserver } from "../job-observer.js";
import { ApiHttpError, createApiClient } from "../api-client.js";
import { createJobOutputReader } from "../job-output-reader.js";

async function settle() {
  for (let index = 0; index < 24; index += 1) await Promise.resolve();
}

class FakeClock {
  time = 10000;
  nextId = 1;
  timers = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => {
    const id = this.nextId++;
    this.timers.set(id, { callback, at: this.time + delay });
    return id;
  };
  clearTimeout = (id) => this.timers.delete(id);
  async advance(milliseconds) {
    const target = this.time + milliseconds;
    for (let count = 0; count < 1000; count += 1) {
      const next = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      this.time = next[1].at;
      this.timers.delete(next[0]);
      next[1].callback();
      await settle();
      assert(count < 999, "fake clock detected an unbounded timer loop");
    }
    this.time = target;
    await settle();
  }
}

function harness({ getJob = async (id) => ({ id, status: "running" }), getJobOutput = async () => [], outputReader } = {}) {
  const clock = new FakeClock();
  const snapshots = [];
  const observer = createJobObserver({
    api: { getJob, getJobOutput },
    outputReader,
    isTerminal: (job) => ["success", "failed", "canceled", "expired"].includes(job.status),
    onChange: (snapshot) => snapshots.push(snapshot),
    clock,
  });
  return { clock, snapshots, observer };
}

function storedPage(items = [], { cursor = "op1.end", more = false, caught = !more, status = "success" } = {}) {
  return { items, next_after: cursor, has_more: more, caught_up: caught, history: "tracked", job_status: status };
}
function storedFragment(n, text = String(n)) {
  return { chunk_key: String(n), agent_id: "a", stream: "stdout", sequence: String(n - 1), offset_bytes: "0",
    total_bytes: String(new TextEncoder().encode(text).length), data: text, chunk_complete: true };
}

test("paged observation yields at four pages, then confirms fresh terminal detail and an open empty read", async () => {
  const calls = []; const pages = Array.from({ length: 5 }, (_, i) => storedPage([storedFragment(i + 1)], { cursor: `op1.c${i + 1}`, more: i < 4 }));
  pages.push(storedPage([], { cursor: "op1.end" }));
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async (_id, options) => {
    calls.push(["page", options.after]); const result = pages.shift(); assert(result); return result;
  } } });
  const { observer, clock } = harness({ outputReader,
    getJob: async (id) => { calls.push(["job"]); return { id, status: "success" }; },
    getJobOutput: async () => { throw new Error("production page reader must not fall back"); },
  });
  observer.select("job-1"); await settle();
  assert.equal(calls.filter(([kind]) => kind === "page").length, 4);
  assert.equal(observer.getSnapshot().phase, "following");
  assert.equal(observer.getSnapshot().output.hasMore, true);
  assert.equal(clock.timers.size, 1);
  await clock.advance(0);
  assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(observer.getSnapshot().output.fragments.length, 5);
  assert.deepEqual(calls.map(([kind]) => kind), ["job", "page", "page", "page", "page", "job", "page", "job", "page"]);
  assert.equal(clock.timers.size, 0);
});

test("a new terminal prefix during verification is drained before another fresh empty confirmation", async () => {
  const pages = [storedPage([storedFragment(1)], { cursor: "op1.a" }), storedPage([storedFragment(2)], { cursor: "op1.b" }), storedPage([], { cursor: "op1.b" })];
  let details = 0;
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async () => pages.shift() } });
  const { observer, clock } = harness({ outputReader, getJob: async (id) => { details += 1; return { id, status: "success" }; } });
  observer.select("job-1"); await settle();
  assert.equal(observer.getSnapshot().phase, "following");
  await clock.advance(0);
  assert.equal(details, 3); assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(observer.getSnapshot().output.fragments.map((f) => f.data).join(""), "12");
});

test("terminal detail does not complete while the page snapshot still reports a nonterminal status", async () => {
  let reads = 0;
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async () => storedPage([], { status: ++reads === 1 ? "running" : "success" }) } });
  const { observer, clock } = harness({ outputReader, getJob: async (id) => ({ id, status: "success" }) });
  observer.select("job-1"); await settle();
  assert.equal(observer.getSnapshot().phase, "following");
  await clock.advance(1000);
  assert.equal(observer.getSnapshot().phase, "completed"); assert.equal(reads, 3);
});

test("page failure stays a local typed error with bounded retry and no legacy output read", async () => {
  for (const [status, kind] of [[409, "output_stale"], [413, "output_limit"], [400, "output_query"]]) {
    let legacy = 0;
    const outputReader = createJobOutputReader({ api: { getJobOutputPage: async () => { throw new ApiHttpError("safe", status); } } });
    const { observer, clock } = harness({ outputReader, getJobOutput: async () => { legacy += 1; return []; } });
    observer.select("job-1"); await settle();
    assert.equal(observer.getSnapshot().phase, "error"); assert.equal(observer.getSnapshot().error.kind, kind);
    assert.equal(observer.getSnapshot().job?.status ?? null, null); assert.equal(clock.timers.size, 0); assert.equal(legacy, 0);
  }
});

test("page cursor and window survive pause but same-ID selection and refresh start a clean context", async () => {
  const calls = []; let pages = 0;
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async (_id, options) => {
    calls.push(options.after); pages += 1;
    if (options.after) return storedPage([], { cursor: options.after });
    return storedPage([storedFragment(1, "first")], { cursor: `op1.c${pages}` });
  } } });
  const { observer, clock } = harness({ outputReader });
  observer.select("job-1"); await settle(); observer.pause();
  assert.equal(observer.getSnapshot().output.fragments.length, 1); assert.equal(clock.timers.size, 0);
  observer.resume(); await settle();
  assert.equal(calls[1], "op1.c1");
  observer.select("job-1"); await settle();
  assert.equal(calls[2], undefined);
  observer.dispose(); assert.equal(outputReader.getSnapshot().fragments.length, 0); assert.equal(clock.timers.size, 0);
});

test("late page response from a retired selection cannot write into the new read owner", async () => {
  const pending = deferred(); const signals = [];
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async (id, { signal }) => {
    signals.push(signal); return id === "A" ? pending.promise : storedPage([storedFragment(1, "B")], { status: "running" });
  } } });
  const { observer } = harness({ outputReader });
  observer.select("A"); await settle(); observer.select("B"); await settle();
  assert.equal(signals[0].aborted, true);
  const before = observer.getSnapshot();
  pending.resolve(storedPage([storedFragment(1, "stale A")])); await settle();
  assert.equal(observer.getSnapshot(), before); assert.equal(before.output.fragments[0].data, "B");
  observer.dispose();
});

test("page observation follows beyond forty-five polls and completes only after fresh terminal confirmation", async () => {
  let reads = 0, legacy = 0, status = "running";
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async () => storedPage([], { status }) } });
  const { observer, clock } = harness({ outputReader,
    getJob: async (id) => { reads += 1; status = reads > 46 ? "success" : "running"; return { id, status }; },
    getJobOutput: async () => { legacy += 1; return []; },
  });
  observer.select("long"); await settle(); await clock.advance(45000);
  assert.equal(reads, 46); assert.equal(observer.getSnapshot().phase, "following");
  await clock.advance(1000);
  assert.equal(reads, 48); assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(legacy, 0); assert.equal(clock.timers.size, 0);
});

test("page pause and immediate resume release the old read before its API promise settles", async () => {
  const first = deferred(); let calls = 0;
  const outputReader = createJobOutputReader({ api: { getJobOutputPage: async () => {
    calls += 1; return calls === 1 ? first.promise : storedPage([storedFragment(1, "resumed")], { status: "running" });
  } } });
  const { observer } = harness({ outputReader });
  observer.select("job"); await settle(); observer.pause(); observer.resume(); await settle();
  try {
    assert.equal(observer.getSnapshot().phase, "following");
    assert.equal(calls, 2); assert.equal(observer.getSnapshot().output.fragments[0].data, "resumed");
    const before = observer.getSnapshot();
    first.resolve(storedPage([storedFragment(1, "retired")])); await settle();
    assert.equal(observer.getSnapshot(), before);
  } finally { first.resolve(storedPage()); await settle(); observer.dispose(); }
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("observes beyond 45 polls and stops only after server terminal plus final output read", async () => {
  let reads = 0;
  let outputs = 0;
  const { observer, clock } = harness({
    getJob: async (id) => ({ id, status: ++reads > 46 ? "success" : "running" }),
    getJobOutput: async () => { outputs += 1; return []; },
  });
  observer.select("long-job");
  await settle();
  assert.equal(reads, 1);
  await clock.advance(45000);
  assert.equal(reads, 46);
  assert.equal(observer.getSnapshot().phase, "following");
  await clock.advance(1000);
  assert.equal(reads, 47);
  assert.equal(outputs, 47);
  assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(clock.timers.size, 0);
  await clock.advance(60000);
  assert.equal(reads, 47);
});

test("terminal completion waits for an output read started after the terminal Job read", async () => {
  const jobRead = deferred();
  const outputRead = deferred();
  const calls = [];
  const job = { id: "job-1", status: "failed", target_agents: [{ agent_id: "a", last_error: "execution_outcome_unknown" }] };
  const chunks = [{ agent_id: "a", stream: "stderr", data: "fixture output" }];
  const { observer, clock } = harness({
    getJob: (_id, { signal }) => { calls.push(["job", signal]); return jobRead.promise; },
    getJobOutput: (_id, { signal }) => { calls.push(["output", signal]); return outputRead.promise; },
  });
  observer.select("job-1");
  assert.equal(calls.length, 1);
  jobRead.resolve(job);
  await settle();
  assert.equal(calls.length, 2);
  assert.equal(calls[0][1], calls[1][1]);
  assert.equal(observer.getSnapshot().phase, "loading");
  outputRead.resolve(chunks);
  await settle();
  assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(observer.getSnapshot().job, job);
  assert.equal(observer.getSnapshot().chunks, chunks);
  assert.equal(clock.timers.size, 0);
});

for (const stage of ["job", "output"]) {
  for (const lateResult of ["success", "failure"]) {
    test(`A→B ignores late A ${stage} ${lateResult} even when the API ignores abort`, async () => {
      const late = deferred();
      let oldSignal;
      let oldOutputCalls = 0;
      const { observer, snapshots, clock } = harness({
        getJob: (id, { signal }) => {
          if (id === "A") {
            oldSignal = signal;
            if (stage === "job") return late.promise;
          }
          return Promise.resolve({ id, status: "running" });
        },
        getJobOutput: (id) => {
          if (id === "A") {
            oldOutputCalls += 1;
            return late.promise;
          }
          return Promise.resolve([{ agent_id: "b", data: "B output" }]);
        },
      });
      observer.select("A");
      await settle();
      observer.select("B");
      await settle();
      assert(oldSignal.aborted);
      const snapshot = observer.getSnapshot();
      const updates = snapshots.length;
      if (lateResult === "success") late.resolve(stage === "job" ? { id: "A", status: "success" } : [{ data: "A output" }]);
      else late.reject(new TypeError("late private error"));
      await settle();
      assert.equal(observer.getSnapshot(), snapshot);
      assert.equal(snapshots.length, updates);
      assert.equal(snapshot.jobId, "B");
      assert.equal(snapshot.chunks[0].data, "B output");
      assert.equal(oldOutputCalls, stage === "job" ? 0 : 1);
      observer.dispose();
      assert.equal(clock.timers.size, 0);
    });
  }
}

test("same Job reselection invalidates its old generation and reads server state again", async () => {
  const old = deferred();
  let calls = 0;
  const { observer, snapshots } = harness({
    getJob: (id) => ++calls === 1 ? old.promise : Promise.resolve({ id, status: "canceled" }),
  });
  observer.select("same");
  observer.select("same");
  await settle();
  const latest = observer.getSnapshot();
  assert.equal(latest.phase, "completed");
  const updates = snapshots.length;
  old.resolve({ id: "same", status: "running" });
  await settle();
  assert.equal(observer.getSnapshot(), latest);
  assert.equal(snapshots.length, updates);
  observer.select("same");
  assert.equal(observer.getSnapshot().job, null);
  assert.equal(observer.getSnapshot().phase, "loading");
  await settle();
  assert.equal(calls, 3);
});

test("pause aborts an active read immediately; resume uses a new signal without waiting for the old read", async () => {
  const old = deferred();
  const signals = [];
  const { observer, clock, snapshots } = harness({
    getJob: (id, { signal }) => {
      signals.push(signal);
      return signals.length === 1 ? old.promise : Promise.resolve({ id, status: "running" });
    },
  });
  observer.select("job-1");
  observer.pause();
  assert(signals[0].aborted);
  assert.equal(clock.timers.size, 0);
  assert.equal(observer.getSnapshot().phase, "paused");
  await clock.advance(60000);
  assert.equal(signals.length, 1);
  observer.resume();
  await settle();
  assert.equal(signals.length, 2);
  assert.notEqual(signals[0], signals[1]);
  const latest = observer.getSnapshot();
  const updates = snapshots.length;
  old.reject(new Error("old raw failure"));
  await settle();
  assert.equal(observer.getSnapshot(), latest);
  assert.equal(snapshots.length, updates);
  observer.dispose();
  assert.equal(clock.timers.size, 0);
});

test("pause and disposal clear scheduled work, preserve canonical results and make disposal permanent", async () => {
  let calls = 0;
  const job = { id: "job-1", status: "pending_approval", target_agents: [] };
  const { observer, clock, snapshots } = harness({ getJob: async () => { calls += 1; return job; } });
  observer.select("job-1");
  await settle();
  observer.pause();
  assert.equal(observer.getSnapshot().job, job);
  assert.equal(clock.timers.size, 0);
  await clock.advance(60000);
  assert.equal(calls, 1);
  observer.resume();
  await settle();
  assert.equal(calls, 2);
  observer.dispose();
  assert.equal(observer.getSnapshot().phase, "disposed");
  const updates = snapshots.length;
  observer.dispose();
  observer.pause();
  await clock.advance(60000);
  assert.equal(snapshots.length, updates);
  assert.equal(calls, 2);
  assert.equal(clock.timers.size, 0);
  assert.throws(() => observer.select("job-1"), /disposed/);
  assert.throws(() => observer.resume(), /disposed/);
});

for (const [status, kind, retryable] of [[401, "authentication", false], [403, "forbidden", false], [404, "not_found", false], [400, "http", false], [429, "http", true], [500, "http", true], [503, "http", true]]) {
  test(`HTTP ${status} is classified without raw error retention or an unbounded retry`, async () => {
    let calls = 0;
    const { observer, clock } = harness({ getJob: async () => { calls += 1; throw new ApiHttpError("must-not-retain-raw-message", status); } });
    observer.select("job-1");
    await settle();
    assert.deepEqual(observer.getSnapshot().error, { kind, status, retryable });
    assert.equal(JSON.stringify(observer.getSnapshot()).includes("must-not-retain"), false);
    assert.equal(observer.getSnapshot().job, null);
    await clock.advance(60000);
    assert.equal(calls, retryable ? 4 : 1);
    assert.equal(observer.getSnapshot().phase, "error");
    assert.equal(observer.getSnapshot().retryAt, null);
    assert.equal(clock.timers.size, 0);
    observer.resume();
    await settle();
    assert.equal(calls, retryable ? 5 : 2);
    observer.dispose();
  });
}

test("network retry uses bounded backoff while retaining the last successful server snapshot", async () => {
  let calls = 0;
  const job = { id: "job-1", status: "running", target_agents: [{ agent_id: "a", assignment_status: "running" }] };
  const chunks = [{ data: "already observed" }];
  const { observer, clock } = harness({
    getJob: async () => { if (++calls > 1) throw new TypeError("private network detail"); return job; },
    getJobOutput: async () => chunks,
  });
  observer.select("job-1");
  await settle();
  const updated = observer.getSnapshot().lastUpdatedAt;
  await clock.advance(1000);
  assert.equal(observer.getSnapshot().retryAt, clock.now() + 1000);
  await clock.advance(999);
  assert.equal(calls, 2);
  await clock.advance(1);
  assert.equal(calls, 3);
  assert.equal(observer.getSnapshot().retryAt, clock.now() + 2000);
  await clock.advance(2000);
  assert.equal(calls, 4);
  await clock.advance(4000);
  assert.equal(calls, 5);
  assert.equal(clock.timers.size, 0);
  assert.equal(observer.getSnapshot().lastUpdatedAt, updated);
  assert.equal(observer.getSnapshot().job, job);
  assert.equal(observer.getSnapshot().chunks, chunks);
  assert.equal(observer.getSnapshot().error.kind, "network");
  assert.equal(JSON.stringify(observer.getSnapshot()).includes("private network detail"), false);
});

test("a stalled API is bounded by deadline and never starts output after timeout", async () => {
  const stalled = deferred();
  let signal;
  let outputs = 0;
  const { observer, clock } = harness({
    getJob: (_id, options) => { signal = options.signal; return stalled.promise; },
    getJobOutput: async () => { outputs += 1; return []; },
  });
  observer.select("job-1");
  await clock.advance(9999);
  assert.equal(clock.timers.size, 1);
  assert.equal(observer.getSnapshot().phase, "loading");
  await clock.advance(1);
  assert(signal.aborted);
  assert.equal(observer.getSnapshot().error.kind, "timeout");
  assert.equal(observer.getSnapshot().retryAt, clock.now() + 1000);
  observer.pause();
  const latest = observer.getSnapshot();
  stalled.resolve({ id: "job-1", status: "success" });
  await settle();
  assert.equal(observer.getSnapshot(), latest);
  assert.equal(outputs, 0);
  assert.equal(clock.timers.size, 0);
});

test("output failure cannot manufacture completed or a canonical failed Job", async () => {
  const { observer, clock } = harness({
    getJob: async (id) => ({ id, status: "success" }),
    getJobOutput: async () => { throw new TypeError("unavailable"); },
  });
  observer.select("job-1");
  await settle();
  assert.equal(observer.getSnapshot().phase, "error");
  assert.equal(observer.getSnapshot().job, null);
  assert.equal(observer.getSnapshot().lastUpdatedAt, null);
  assert.equal(clock.timers.size, 1);
  observer.dispose();
});

for (const invalid of ["missing", "other-job", "invalid-output"]) {
  test(`invalid ${invalid} response is explicit, not a successful empty snapshot`, async () => {
    const { observer, clock } = harness({
      getJob: async (id) => invalid === "missing" ? null : ({ id: invalid === "other-job" ? "wrong-id" : id, status: "running" }),
      getJobOutput: async () => invalid === "invalid-output" ? null : [],
    });
    observer.select("job-1");
    await settle();
    assert.equal(observer.getSnapshot().phase, "error");
    assert.equal(observer.getSnapshot().error.kind, "invalid_response");
    assert.equal(observer.getSnapshot().lastUpdatedAt, null);
    assert.equal(clock.timers.size, 0);
  });
}

test("a valid read resets the consecutive failure budget and output does not imply terminal", async () => {
  let calls = 0;
  const { observer, clock } = harness({
    getJob: async (id) => { if (++calls !== 2) throw new TypeError("offline"); return { id, status: "running" }; },
    getJobOutput: async () => [{ data: "not a completion signal" }],
  });
  observer.select("job-1");
  await settle();
  await clock.advance(1000);
  assert.equal(observer.getSnapshot().phase, "following");
  await clock.advance(1000);
  assert.equal(observer.getSnapshot().retryAt, clock.now() + 1000);
  await clock.advance(7000);
  assert.equal(calls, 6);
  assert.equal(clock.timers.size, 0);
  observer.dispose();
});

test("disposal aborts output immediately and ignores its late rejection", async () => {
  const output = deferred();
  let signal;
  const { observer, snapshots, clock } = harness({ getJobOutput: (_id, options) => { signal = options.signal; return output.promise; } });
  observer.select("job-1");
  await settle();
  observer.dispose();
  assert(signal.aborted);
  assert.equal(clock.timers.size, 0);
  const disposed = observer.getSnapshot();
  const updates = snapshots.length;
  output.reject(new Error("late output failure"));
  await settle();
  assert.equal(observer.getSnapshot(), disposed);
  assert.equal(snapshots.length, updates);
});

test("reentrant selection from a view callback cannot restart the retired owner", async () => {
  const clock = new FakeClock();
  const calls = [];
  let observer;
  observer = createJobObserver({
    api: {
      getJob: async (id) => { calls.push(id); return { id, status: "running" }; },
      getJobOutput: async () => [],
    },
    isTerminal: () => false,
    onChange: (state) => { if (state.jobId === "A" && state.phase === "following") observer.select("B"); },
    clock,
  });
  observer.select("A");
  await settle();
  await clock.advance(1000);
  assert.deepEqual(calls, ["A", "B", "B"]);
  assert.equal(observer.getSnapshot().jobId, "B");
  assert.equal(clock.timers.size, 1);
  observer.dispose();
});

test("view callback failure stops observation without being retried as network failure", async () => {
  const clock = new FakeClock();
  let calls = 0;
  const observer = createJobObserver({
    api: {
      getJob: async (id) => { calls += 1; return { id, status: "running" }; },
      getJobOutput: async () => [],
    },
    isTerminal: () => false,
    onChange: (state) => { if (state.phase === "following") throw new TypeError("private view failure"); },
    clock,
  });
  observer.select("job-1");
  await settle();
  assert.equal(observer.getSnapshot().error.kind, "view");
  assert.equal(observer.getSnapshot().job.status, "running");
  assert.equal(JSON.stringify(observer.getSnapshot()).includes("private view failure"), false);
  assert.equal(clock.timers.size, 0);
  await clock.advance(60000);
  assert.equal(calls, 1);
  observer.dispose();
});

test("terminal policy is supplied by the caller and is not inferred from an unfamiliar status", async () => {
  const clock = new FakeClock();
  const observer = createJobObserver({
    api: {
      getJob: async (id) => ({ id, status: "future-server-status", terminal_from_server: true }),
      getJobOutput: async () => [],
    },
    isTerminal: (job) => job.terminal_from_server === true,
    onChange: () => {},
    clock,
  });
  observer.select("job-1");
  await settle();
  assert.equal(observer.getSnapshot().phase, "completed");
  assert.equal(clock.timers.size, 0);
});

test("the real API client shares the owner's signal across Job/output reads and cancellation", async () => {
  const clock = new FakeClock();
  const requests = [];
  const pendingOutput = deferred();
  const api = createApiClient({ fetchImpl: (path, options) => {
    requests.push({ path, signal: options.signal });
    return path.endsWith("/output") ? pendingOutput.promise : Promise.resolve({
      ok: true, status: 200, json: async () => ({ id: "job/1", status: "running" }),
    });
  } });
  const observer = createJobObserver({ api, isTerminal: () => false, onChange: () => {}, clock });
  observer.select("job/1");
  await settle();
  assert.deepEqual(requests.map((item) => item.path), ["/api/jobs/job%2F1", "/api/jobs/job%2F1/output"]);
  assert.equal(requests[0].signal, requests[1].signal);
  observer.dispose();
  assert(requests[1].signal.aborted);
  pendingOutput.resolve({ ok: true, status: 200, json: async () => [{ data: "late" }] });
  await settle();
  assert.equal(observer.getSnapshot().phase, "disposed");
  assert.equal(observer.getSnapshot().lastUpdatedAt, null);
  assert.equal(clock.timers.size, 0);
});
