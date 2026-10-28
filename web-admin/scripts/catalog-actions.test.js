import test from "node:test";
import assert from "node:assert/strict";

const commit = "a".repeat(40);
const settle = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
const operation = (state = "in_progress", extra = {}) => ({ id: "canonical-sync", source_id: "source-a", state,
  commit: state === "completed" ? commit : null, failure: state === "failed" ? "fetch_failed" : null, ...extra });
const context = (selection = null) => ({ route: "runbooks", authenticated: true, selection });
const selection = () => ({ sourceId: "source-a", commit, state: "ready", stale: false, activeCommit: "b".repeat(40) });

async function harness(overrides = {}) {
  const { createCatalogActions } = await import("../catalog-actions.js");
  let now = 0, serial = 0; const timers = new Map(), calls = [], changes = [], committed = [];
  const clock = { now: () => now, setTimeout(fn, ms) { timers.set(++serial, { fn, at: now + ms }); return serial; }, clearTimeout(id) { timers.delete(id); } };
  const api = {
    startCatalogSync(...args) { calls.push(["start", ...args]); return (overrides.start || (() => ({ id: "canonical-sync", source_id: "source-a", state: "in_progress" })))(...args); },
    getCatalogSyncOperation(...args) { calls.push(["read", ...args]); return (overrides.read || (() => operation()))(...args); },
    activateCatalogRevision(...args) { calls.push(["activate", ...args]); return (overrides.activate || (() => ({ id: "source-a", active_commit: commit })))(...args); },
    registerCatalogSource(...args) { calls.push(["register", ...args]); return { id: args[0].source_id }; },
  };
  const owner = createCatalogActions({ api, clock, onChange: view => changes.push(view), onCommitted: action => committed.push(action) });
  owner.setContext(context());
  async function advance(ms) {
    const until = now + ms;
    while (true) {
      const next = [...timers].filter(([, value]) => value.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break; now = next[1].at; timers.delete(next[0]); next[1].fn(); await settle();
    }
    now = until; await settle();
  }
  return { owner, calls, changes, committed, timers, advance };
}

test("sync acceptance follows the returned canonical ID and only the status GET establishes completion", async () => {
  let reads = 0;
  const h = await harness({ read: () => ++reads === 1 ? operation() : operation("completed") });
  await h.owner.submit("sync", { sourceId: "source-a", operationId: "requested-sync" }); await settle();
  assert.equal(h.owner.getSnapshot().operation.state, "in_progress");
  assert.match(h.owner.getSnapshot().message, /in progress/i);
  assert.equal(h.calls.find(call => call[0] === "read")[2], "canonical-sync");
  await h.advance(1000);
  assert.equal(h.owner.getSnapshot().operation.state, "completed");
  assert.equal(h.owner.getSnapshot().observation, "done");
  assert.equal(h.calls.filter(call => call[0] === "activate").length, 0);
  assert.equal(h.timers.size, 0); h.owner.dispose();
});

test("duplicate sync clicks and an ambiguous POST timeout never automatically resubmit a mutation", async () => {
  const wait = deferred(); const h = await harness({ start: () => wait.promise });
  const first = h.owner.submit("sync", { sourceId: "source-a", operationId: "requested-sync" });
  await h.owner.submit("sync", { sourceId: "source-a", operationId: "requested-sync" });
  await h.advance(10000); await first;
  assert.match(h.owner.getSnapshot().message, /unknown/i);
  assert.equal(h.calls.filter(call => call[0] === "start").length, 1);
  assert.equal(h.calls.filter(call => call[0] === "read").length, 0);
  wait.resolve({ id: "canonical-sync", source_id: "source-a", state: "in_progress" }); await settle();
  assert.equal(h.owner.getSnapshot().operation, null);
  await h.advance(180000); assert.equal(h.calls.length, 1); h.owner.dispose();
});

test("route, auth and selected revision changes abort owned reads and suppress late successes and errors", async () => {
  for (const next of [{ route: "run", authenticated: true }, { route: "runbooks", authenticated: false }, context(selection())]) {
    const wait = deferred(); const h = await harness({ read: () => wait.promise });
    void h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" }); await settle();
    const signal = h.calls[0][3].signal;
    h.owner.setContext(next); assert.equal(signal.aborted, true);
    wait.resolve(operation("completed")); await settle();
    assert.equal(h.owner.getSnapshot().operation, null); assert.equal(h.timers.size, 0); h.owner.dispose();
  }
});

test("failed and cancelled are canonical results and never activate or replace the active revision", async () => {
  for (const state of ["failed", "cancelled"]) {
    const h = await harness({ read: () => operation(state) });
    h.owner.setContext(context(selection()));
    await h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" });
    assert.equal(h.owner.getSnapshot().operation.state, state);
    assert.equal(h.calls.filter(call => call[0] === "activate").length, 0);
    assert.equal(h.timers.size, 0); h.owner.dispose();
  }
});

test("status identity conflicts, malformed bodies and protected errors stop with safe guidance", async () => {
  for (const result of [operation("completed", { source_id: "other" }), operation("completed", { commit: null }), { ...operation(), body: "private" }, 401, 403, 404]) {
    const h = await harness({ read: () => { if (typeof result === "number") throw Object.assign(new Error("private SQL/password"), { status: result }); return result; } });
    await h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" });
    assert.equal(h.owner.getSnapshot().observation, "stopped");
    assert(!h.owner.getSnapshot().message.includes("private"));
    await h.advance(300000); assert.equal(h.calls.length, 1); h.owner.dispose();
  }
});

test("transient read failures use bounded backoff and observation has an explicit total deadline", async () => {
  const h = await harness({ read: () => { throw new Error("offline"); } });
  await h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" });
  await h.advance(20000);
  assert.equal(h.calls.length, 3); assert.equal(h.owner.getSnapshot().observation, "stopped");
  assert.equal(h.timers.size, 0); h.owner.dispose();
  const live = await harness();
  await live.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" });
  await live.advance(180000);
  assert.equal(live.owner.getSnapshot().observation, "stopped");
  assert.equal(live.owner.getSnapshot().operation.state, "in_progress");
  assert.match(live.owner.getSnapshot().message, /observation.*stopped/i);
  assert.equal(live.timers.size, 0); live.owner.dispose();
});

test("activation requires the exact selected ready revision, explicit confirmation and current context", async () => {
  const h = await harness(); h.owner.setContext(context(selection()));
  await h.owner.submit("activate", { sourceId: "source-a", commit });
  assert.equal(h.calls.length, 0); assert.equal(h.owner.getSnapshot().confirmation.commit, commit);
  h.owner.cancelActivation(); await h.owner.confirmActivation(); assert.equal(h.calls.length, 0);
  await h.owner.submit("activate", { sourceId: "source-a", commit: "c".repeat(40) });
  assert.equal(h.owner.getSnapshot().confirmation, null);
  await h.owner.submit("activate", { sourceId: "source-a", commit });
  h.owner.setContext(context({ ...selection(), commit: "c".repeat(40) }));
  await h.owner.confirmActivation(); assert.equal(h.calls.length, 0);
  h.owner.setContext(context(selection()));
  await h.owner.submit("activate", { sourceId: "source-a", commit }); await h.owner.confirmActivation();
  assert.equal(h.calls[0][0], "activate"); assert.deepEqual(h.calls[0][2], { commit });
  assert.deepEqual(h.committed, ["activate"]); h.owner.dispose();
});

test("late mutation success after navigation cannot refresh a new selection or announce completion", async () => {
  const wait = deferred(); const h = await harness({ activate: () => wait.promise });
  h.owner.setContext(context(selection()));
  await h.owner.submit("activate", { sourceId: "source-a", commit }); const confirming = h.owner.confirmActivation();
  h.owner.setContext({ route: "policies", authenticated: true });
  wait.resolve({ id: "source-a", active_commit: commit }); await confirming;
  assert.deepEqual(h.committed, []); assert.equal(h.owner.getSnapshot().message, "");
  assert.equal(h.timers.size, 0); h.owner.dispose();
});

test("manual stop and disposal retire pending reads even if the API ignores abort", async () => {
  const wait = deferred(); const h = await harness({ read: () => wait.promise });
  const pending = h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" }); await settle();
  h.owner.stopObservation(); await pending;
  assert.equal(h.calls[0][3].signal.aborted, true); assert.equal(h.timers.size, 0);
  h.owner.dispose(); wait.reject(new Error("retired")); await settle(); assert.equal(h.calls.length, 1);
});

test("immediate stop and resume cannot let the old read finish or retry the new observation", async () => {
  const old = deferred(), fresh = deferred(); let reads = 0;
  const h = await harness({ read: () => ++reads === 1 ? old.promise : fresh.promise });
  const first = h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" }); await settle();
  h.owner.stopObservation();
  const second = h.owner.resumeSync({ sourceId: "source-a", operationId: "canonical-sync" }); await settle();
  assert.equal(h.owner.getSnapshot().observation, "reading");
  assert.match(h.owner.getSnapshot().message, /checking/i);
  fresh.resolve(operation("completed")); await second; await first;
  old.resolve(operation("failed")); await settle();
  assert.equal(h.owner.getSnapshot().operation.state, "completed");
  assert.equal(h.timers.size, 0); h.owner.dispose();
});

test("a malformed accepted response with no canonical ID cannot start an unscoped status read", async () => {
  const h = await harness({ start: () => ({ source_id: "source-a", state: "in_progress" }) });
  await h.owner.submit("sync", { sourceId: "source-a", operationId: "requested-sync" });
  assert.equal(h.calls.length, 1); assert.equal(h.owner.getSnapshot().operation, null);
  assert.match(h.owner.getSnapshot().message, /unknown/); h.owner.dispose();
});

test("an accepted sync is labelled with its canonical ID while the first status read is still pending", async () => {
  const wait = deferred(), h = await harness({ read: () => wait.promise });
  const pending = h.owner.submit("sync", { sourceId: "source-a", operationId: "requested-sync" }); await settle();
  assert.match(h.owner.getSnapshot().message, /accepted.*canonical-sync/i);
  assert.equal(h.owner.getSnapshot().operation, null);
  h.owner.stopObservation(); await pending; wait.resolve(operation()); h.owner.dispose();
});
