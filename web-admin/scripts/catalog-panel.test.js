import test from "node:test";
import assert from "node:assert/strict";
import * as app from "../app.js";

const commitA = "a".repeat(40), commitB = "b".repeat(40);
const source = id => ({ id, url: "https://example.com/catalog.git", reference: "main", active_commit: commitA });
const revision = commit => ({ commit, state: "ready", document_count: 1, failure: null });
const doc = path => ({ path, kind: "runbook", checksum: "c".repeat(64) });
const page = (items, next_after = null) => ({ items, next_after });
const settle = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }

class Element extends EventTarget {
  constructor(document) { super(); this.ownerDocument = document; }
  textContent = "";
  disabled = false;
  dataset = {};
  attributes = {};
  rows = [];
  _html = "";
  writes = 0;
  classList = { toggle() {} };
  setAttribute(name, value) { this.attributes[name] = value; }
  getAttribute(name) { return this.attributes[name]; }
  focus(options) { this.ownerDocument.activeElement = this; this.focusOptions = options; }
  click() { if (!this.disabled) this.dispatchEvent(new Event("click")); }
  get innerHTML() {
    let index = 0;
    // A real parent serializes the attributes changed on its child buttons.
    return this._html.replace(/(<button\b[^>]*)(>)/g, (_all, opening, closing) => {
      const row = this.rows[index++];
      return opening + Object.entries(row?.attributes || {}).map(([name, value]) => ` ${name}="${value}"`).join("") + closing;
    });
  }
  set innerHTML(value) {
    if (this.rows.includes(this.ownerDocument.activeElement)) this.ownerDocument.activeElement = null;
    this._html = value; this.writes++;
    this.rows = [...value.matchAll(/data-catalog-(source-id|commit|path)="([^"]*)"/g)].map((match) => {
      const row = new Element(this.ownerDocument);
      row.dataset[{ "source-id": "catalogSourceId", commit: "catalogCommit", path: "catalogPath" }[match[1]]] = match[2];
      row.closest = () => row;
      return row;
    });
  }
  querySelectorAll() { return this.rows; }
  contains(element) { return this === element || this.rows.includes(element); }
  choose(index = 0) {
    const row = this.rows[index]; row.focus({ preventScroll: true });
    const event = new Event("click"); Object.defineProperty(event, "target", { value: row }); this.dispatchEvent(event); return row;
  }
}

function harness(overrides = {}) {
  assert.equal(typeof app.createCatalogPanel, "function", "app must compose the Catalog read owner into the real panel");
  const document = { activeElement: null }, timers = new Map(); let nextTimer = 0;
  const elements = { selection: new Element(document), ...Object.fromEntries(["sources", "revisions", "documents"].map(level => [level,
    Object.fromEntries(["list", "status", "first", "next", "retry"].map(key => [key, new Element(document)]))])) };
  const calls = [];
  const apiClient = {
    listCatalogSources: options => { calls.push(["sources", options]); return (overrides.sources || (() => page([source("a")], "sources-next")))(options); },
    listCatalogRevisions: (id, options) => { calls.push(["revisions", options]); return (overrides.revisions || (() => page([revision(commitA)], "revisions-next")))(id, options); },
    listCatalogDocuments: (id, commit, options) => { calls.push(["documents", options]); return (overrides.documents || (() => page([doc("a.yaml")], "documents-next")))(id, commit, options); },
  };
  const panel = app.createCatalogPanel({ apiClient, elements, clock: { setTimeout: fn => { timers.set(++nextTimer, fn); return nextTimer; }, clearTimeout: id => timers.delete(id) } });
  return { panel, elements, document, timers, calls };
}

test("the real Catalog panel renders and navigates all three lists without fetching a document body", async () => {
  const h = harness({
    sources: ({ after }) => after ? page([source("b")]) : page([source("a")], "next-source"),
    revisions: (_id, { after }) => after ? page([revision(commitB)]) : page([revision(commitA)], "next-revision"),
    documents: (_id, _commit, { after }) => after ? page([doc("b.yaml")]) : page([doc("a.yaml")], "next-document"),
  });
  await h.panel.setContext({ route: "runbooks", authenticated: true });
  assert.match(h.elements.sources.list.innerHTML, /data-catalog-source-id="a"/);
  h.elements.sources.list.choose(); await settle(); h.elements.revisions.list.choose(); await settle();
  h.elements.documents.list.choose(); await settle();
  assert.equal(h.panel.getSnapshot().selectedDocument.path, "a.yaml");
  h.elements.documents.next.click(); await settle(); assert.match(h.elements.documents.list.innerHTML, /b.yaml/);
  h.elements.revisions.next.click(); await settle(); h.elements.sources.next.click(); await settle();
  assert.match(h.elements.sources.list.innerHTML, /data-catalog-source-id="b"/);
  assert.match(h.elements.selection.textContent, /a.yaml/); assert(h.calls.every(([level]) => ["sources", "revisions", "documents"].includes(level)));
  assert.equal(h.elements.sources.next.disabled, true); assert.equal(h.timers.size, 0); h.panel.dispose();
});

test("explicit selection preserves keyboard focus on the same row instead of replacing its DOM", async () => {
  const h = harness(); await h.panel.setContext({ route: "runbooks", authenticated: true });
  const row = h.elements.sources.list.choose(); await settle();
  assert.equal(h.document.activeElement, row); assert.equal(row.getAttribute("aria-pressed"), "true");
  assert.deepEqual(row.focusOptions, { preventScroll: true }); h.panel.dispose();
});

test("pending next-page navigation keeps focus, ignores repeated activation and focuses results at the last page", async () => {
  const wait = deferred();
  const h = harness({ sources: ({ after }) => after ? wait.promise : page([source("a")], "next") });
  await h.panel.setContext({ route: "runbooks", authenticated: true });
  h.elements.sources.next.focus(); h.elements.sources.next.click(); await settle();
  assert.equal(h.document.activeElement, h.elements.sources.next);
  h.elements.sources.next.click(); await settle(); assert.equal(h.calls.length, 2);
  wait.resolve(page([source("b")])); await settle();
  assert.equal(h.document.activeElement, h.elements.sources.list); assert.equal(h.elements.sources.next.disabled, true); h.panel.dispose();
});

test("late errors cannot repaint the selected parent, and logout removes metadata and pending reads", async () => {
  const wait = deferred(); let reads = 0;
  const h = harness({ sources: () => page([source("a"), source("b")]), revisions: () => ++reads === 1 ? wait.promise : page([revision(commitB)]) });
  await h.panel.setContext({ route: "runbooks", authenticated: true });
  h.elements.sources.list.choose(0); await settle(); h.elements.sources.list.choose(1); await settle();
  wait.reject(new Error("obsolete sensitive failure")); await settle();
  assert.match(h.elements.revisions.list.innerHTML, new RegExp(commitB.slice(0, 12)));
  assert(!h.elements.revisions.status.textContent.includes("sensitive"));
  await h.panel.setContext({ route: "runbooks", authenticated: false });
  assert(!h.elements.sources.list.innerHTML.includes('data-catalog-source-id="'));
  assert.equal(h.timers.size, 0); assert.equal(h.panel.getSnapshot().selectedSource, null); h.panel.dispose();
});

test("forbidden metadata is explicit and an explicit retry can recover without automatic work", async () => {
  let reads = 0;
  const h = harness({ sources: () => { if (++reads === 1) throw Object.assign(new Error("raw private detail"), { status: 403 }); return page([]); } });
  await h.panel.setContext({ route: "policies", authenticated: true });
  assert.match(h.elements.sources.status.textContent, /Permission denied/); assert.equal(h.elements.sources.retry.disabled, false);
  assert.equal(h.calls.length, 1); assert(!h.elements.sources.status.textContent.includes("private"));
  h.elements.sources.retry.click(); await settle(); assert.match(h.elements.sources.status.textContent, /No catalog sources/);
  assert.equal(h.calls.length, 2); h.panel.dispose();
});

test("disposing the panel removes its delegated and control listeners", async () => {
  const h = harness(); await h.panel.setContext({ route: "runbooks", authenticated: true }); h.panel.dispose();
  const before = h.calls.length; h.elements.sources.first.click(); h.elements.sources.next.click(); await settle();
  assert.equal(h.calls.length, before); assert.equal(h.timers.size, 0);
});

test("revision labels distinguish commits that share the leading twelve characters", () => {
  const other = `${"a".repeat(39)}b`;
  const html = app.renderCatalogRevisions([revision(commitA), revision(other)]);
  assert(html.includes("aaaaaaaaaaaa…aaaaaaaa"));
  assert(html.includes("aaaaaaaaaaaa…aaaaaaab"));
});
