import test from "node:test";
import assert from "node:assert/strict";
import { createCatalogExplorer } from "../catalog-explorer.js";

const commitA = "a".repeat(40), commitB = "b".repeat(40);
const source = (id, active = commitA) => ({ id, url: "https://example.com/catalog.git", reference: "main", active_commit: active });
const revision = (commit = commitA) => ({ commit, state: "ready", document_count: 1, failure: null });
const document = (path = "runbooks/a.yaml") => ({ path, kind: "runbook", checksum: "c".repeat(64) });
const page = (items = [], next_after = null) => ({ items, next_after });
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function harness(overrides = {}) {
  const calls = [], states = [], timers = new Map(); let timerId = 0;
  const api = Object.fromEntries(["listCatalogSources", "listCatalogRevisions", "listCatalogDocuments"].map((method) => [method,
    (...args) => { calls.push({ method, args }); return (overrides[method] || (() => page()))(...args); }]));
  const explorer = createCatalogExplorer({ api, onChange: (snapshot) => { states.push(snapshot); overrides.onChange?.(snapshot); },
    clock: { setTimeout: (fn) => { timers.set(++timerId, fn); return timerId; }, clearTimeout: (id) => timers.delete(id) } });
  return { explorer, calls, states, timers };
}

test("three metadata lists reach their second page without discarding explicit parent selection", async () => {
  const h = harness({
    listCatalogSources: ({ after }) => after ? page([source("b")]) : page([source("a")], "opaque-source-next"),
    listCatalogRevisions: (_id, { after }) => after ? page([revision(commitB)]) : page([revision()], "opaque-revision-next"),
    listCatalogDocuments: (_id, _commit, { after }) => after ? page([document("runbooks/b.yaml")]) : page([document()], "opaque-document-next"),
  });
  await h.explorer.setContext({ route: "runbooks", authenticated: true });
  assert.equal(h.calls.length, 1); assert.equal(h.explorer.getSnapshot().selectedSource, null);
  await h.explorer.selectSource("a"); await h.explorer.selectRevision(commitA);
  h.explorer.selectDocument("runbooks/a.yaml");
  await h.explorer.load("documents", { next: true });
  assert.deepEqual(h.explorer.getSnapshot().documents.items.map(d => d.path), ["runbooks/b.yaml"]);
  assert.equal(h.explorer.getSnapshot().selectedDocument.path, "runbooks/a.yaml");
  await h.explorer.load("revisions", { next: true }); await h.explorer.load("sources", { next: true });
  const snapshot = h.explorer.getSnapshot();
  assert.deepEqual(snapshot.sources.items.map(s => s.id), ["b"]); assert.equal(snapshot.selectedSource.id, "a");
  assert.deepEqual(snapshot.revisions.items.map(r => r.commit), [commitB]); assert.equal(snapshot.selectedRevision.commit, commitA);
  assert.equal(h.calls.filter(c => c.method === "listCatalogDocuments").at(-1).args[2].after, "opaque-document-next");
  assert(h.calls.every(c => c.args.at(-1).signal instanceof AbortSignal));
  assert.equal(h.timers.size, 0); assert(Object.isFrozen(snapshot)); h.explorer.dispose();
});

test("old source success and error cannot replace the current revision list, including same-ID reselection", async () => {
  for (const outcome of ["success", "error"]) {
    const old = deferred(); let revisionReads = 0;
    const h = harness({ listCatalogSources: () => page([source("a"), source("b")]),
      listCatalogRevisions: () => ++revisionReads === 1 ? old.promise : page([revision(commitB)]) });
    await h.explorer.setContext({ route: "runbooks", authenticated: true });
    const first = h.explorer.selectSource("a"); await settle();
    const signal = h.calls.find(c => c.method === "listCatalogRevisions").args.at(-1).signal;
    await h.explorer.selectSource(outcome === "success" ? "b" : "a");
    assert(signal.aborted);
    outcome === "error" ? old.reject(new Error("private obsolete failure")) : old.resolve(page([revision()]));
    await first; await settle();
    assert.equal(h.explorer.getSnapshot().revisions.items[0].commit, commitB);
    assert.equal(h.explorer.getSnapshot().revisions.phase, "ready"); h.explorer.dispose();
  }
});

test("revision switch retires document reads and clears the prior selected document", async () => {
  const old = deferred();
  const h = harness({ listCatalogSources: () => page([source("a")]), listCatalogRevisions: () => page([revision(), revision(commitB)]),
    listCatalogDocuments: (_source, commit) => commit === commitA ? old.promise : page([document("new.yaml")]) });
  await h.explorer.setContext({ route: "runbooks", authenticated: true }); await h.explorer.selectSource("a");
  const first = h.explorer.selectRevision(commitA); await settle(); await h.explorer.selectRevision(commitB);
  old.reject(new Error("old body")); await first;
  assert.equal(h.explorer.getSnapshot().documents.items[0].path, "new.yaml"); assert.equal(h.explorer.getSnapshot().selectedDocument, null); h.explorer.dispose();
});

test("route/auth exit cancels even an API ignoring abort and leaves no timer, cached selection or late effect", async () => {
  for (const context of [{ route: "run", authenticated: true }, { route: "runbooks", authenticated: false }]) {
    const wait = deferred(); const h = harness({ listCatalogSources: () => wait.promise });
    const read = h.explorer.setContext({ route: "runbooks", authenticated: true }); await settle();
    assert.equal(h.calls.length, 1); const signal = h.calls[0].args[0].signal;
    await h.explorer.setContext(context); await read;
    assert(signal.aborted); assert.equal(h.timers.size, 0); assert.equal(h.explorer.getSnapshot().sources.items.length, 0);
    const writes = h.states.length; wait.resolve(page([source("late")])); await settle(); assert.equal(h.states.length, writes); h.explorer.dispose();
  }
});

test("malformed, duplicate and repeated-cursor pages stop without silently skipping or accepting document bodies", async () => {
  for (const response of [null, { items: [], next_after: 4 }, page([source("a"), source("a")]), page([], "next"), page(Array(51).fill(source("a")))]) {
    const h = harness({ listCatalogSources: () => response }); await h.explorer.setContext({ route: "runbooks", authenticated: true });
    assert.equal(h.explorer.getSnapshot().sources.error.kind, "invalid_response"); assert.equal(h.explorer.getSnapshot().sources.items.length, 0); h.explorer.dispose();
  }
  const h = harness({ listCatalogSources: ({ after }) => after ? page([source("b")], "same") : page([source("a")], "same"),
    listCatalogRevisions: () => page([revision()]), listCatalogDocuments: () => page([{ ...document(), body: "must not retain" }]) });
  await h.explorer.setContext({ route: "runbooks", authenticated: true }); await h.explorer.selectSource("a"); await h.explorer.selectRevision(commitA);
  assert.equal(h.explorer.getSnapshot().documents.error.kind, "invalid_response");
  assert(!JSON.stringify(h.explorer.getSnapshot()).includes("must not retain"));
  await h.explorer.load("sources", { next: true }); assert.equal(h.explorer.getSnapshot().sources.error.kind, "invalid_response"); h.explorer.dispose();
});

test("HTTP and timeout failures have safe explicit states with user-driven retry and a fresh deadline", async () => {
  for (const [status, kind] of [[401, "authentication"], [403, "forbidden"], [404, "not_found"], [500, "http"]]) {
    const h = harness({ listCatalogSources: () => { throw Object.assign(new Error("raw sensitive backend detail"), { status }); } });
    await h.explorer.setContext({ route: "policies", authenticated: true });
    assert.equal(h.explorer.getSnapshot().sources.error.kind, kind); assert.equal(h.calls.length, 1);
    assert(!JSON.stringify(h.explorer.getSnapshot()).includes("sensitive")); assert.equal(h.timers.size, 0); h.explorer.dispose();
  }
  const wait = deferred(); let reads = 0;
  const h = harness({ listCatalogSources: () => ++reads === 1 ? wait.promise : page([source("a")]) });
  const read = h.explorer.setContext({ route: "policies", authenticated: true }); await settle();
  [...h.timers.values()][0](); await read;
  assert.equal(h.explorer.getSnapshot().sources.error.kind, "timeout"); assert.equal(h.timers.size, 0);
  await h.explorer.load("sources", { retry: true }); assert.equal(h.explorer.getSnapshot().sources.phase, "ready"); h.explorer.dispose();
});

test("refreshing an active pointer keeps the explicit immutable revision and marks its old selection stale", async () => {
  let active = commitA;
  const h = harness({ listCatalogSources: () => page([source("a", active)]), listCatalogRevisions: () => page([revision(), revision(commitB)]), listCatalogDocuments: () => page([document()]) });
  await h.explorer.setContext({ route: "runbooks", authenticated: true }); await h.explorer.selectSource("a"); await h.explorer.selectRevision(commitA); h.explorer.selectDocument("runbooks/a.yaml");
  active = commitB; await h.explorer.load("sources");
  const snapshot = h.explorer.getSnapshot(); assert.equal(snapshot.selectedSource.active_commit, commitB); assert.equal(snapshot.selectedRevision.commit, commitA);
  assert.equal(snapshot.selectionStale, true); assert.equal(snapshot.selectedDocument.path, "runbooks/a.yaml"); h.explorer.dispose();
});

test("view callback failure stops owned reads instead of being retried as a network error", async () => {
  const h = harness({ onChange: snapshot => { if (snapshot.sources.phase === "loading") throw new Error("view failed"); } });
  await h.explorer.setContext({ route: "runbooks", authenticated: true });
  assert.equal(h.calls.length, 0); assert.equal(h.timers.size, 0);
  assert.equal(h.explorer.getSnapshot().sources.error.kind, "view");
  await h.explorer.load("sources", { retry: true }); assert.equal(h.calls.length, 0); h.explorer.dispose();
});

test("same-route authenticated identity changes retire catalog requests and selection",async()=>{
  const old=deferred();let count=0;
  const h=harness({listCatalogSources:()=>++count===1?old.promise:page([source("B")])});
  const reading=h.explorer.setContext({route:"runbooks",authenticated:true,authGeneration:1});
  await settle();
  const oldSignal=h.calls[0].args[0].signal;
  await h.explorer.setContext({route:"runbooks",authenticated:true,authGeneration:2});
  old.resolve(page([source("private-A")]));await reading;await settle();
  assert.equal(oldSignal.aborted,true);
  assert.deepEqual(h.explorer.getSnapshot().sources.items.map(item=>item.id),["B"]);
  assert.equal(h.timers.size,0);h.explorer.dispose();
});
