import test from "node:test";
import assert from "node:assert/strict";
import * as app from "../app.js";

const commit = "a".repeat(40);
const settle = async () => { for (let i = 0; i < 50; i++) await Promise.resolve(); };
class Element extends EventTarget {
  value = ""; textContent = ""; disabled = false; hidden = false; open = false;
  dataset = {}; buttons = [];
  focusCalls = 0;
  focus() { this.focusCalls++; }
  querySelectorAll() { return this.buttons; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  click() { if (!this.disabled) this.dispatchEvent(new Event("click")); }
  submit(action) { const event = new Event("submit", { cancelable: true }); Object.defineProperty(event, "submitter", { value: this.buttons.find(button => button.value === action) || { value: action } }); this.dispatchEvent(event); }
}
function harness() {
  assert.equal(typeof app.createCatalogActionPanel, "function");
  const elements = Object.fromEntries(["form", "status", "operation", "check", "stop", "resume", "dialog", "details", "confirm", "cancel"].map(key => [key, new Element()]));
  elements.fields = Object.fromEntries(["sourceId", "operationId", "url", "reference", "commit"].map(key => [key, new Element()]));
  elements.form.buttons = [new Element(), new Element(), new Element()];
  elements.form.buttons.forEach((button, index) => { button.value = ["register", "sync", "activate"][index]; });
  const calls = [], timers = new Map(); let serial = 0;
  const panel = app.createCatalogActionPanel({ elements, apiClient: {
    startCatalogSync: (id, body) => { calls.push(["sync", id, body]); return { id: "canonical-sync", source_id: id, state: "in_progress" }; },
    getCatalogSyncOperation: (id, operationId) => { calls.push(["read", id, operationId]); return { id: operationId, source_id: id, state: "completed", commit, failure: null }; },
    activateCatalogRevision: (id, body) => { calls.push(["activate", id, body]); return { id, active_commit: body.commit }; },
  }, clock: { now: () => 0, setTimeout(fn) { timers.set(++serial, fn); return serial; }, clearTimeout: id => timers.delete(id) } });
  panel.setContext({ route: "runbooks", authenticated: true });
  const select = (overrides = {}) => panel.setSelection({ selectedSource: { id: "source-a", active_commit: null },
    selectedRevision: { commit, state: "ready" }, selectedDocument: null, selectionStale: false, ...overrides });
  return { panel, elements, calls, timers, select };
}

test("the real form follows canonical sync status and offers explicit source/operation checks", async () => {
  const h = harness(); h.select(); h.elements.fields.operationId.value = "requested-sync";
  h.elements.form.submit("sync"); await settle();
  assert.equal(h.calls[0][0], "sync"); assert.equal(h.calls[1][2], "canonical-sync");
  assert.match(h.elements.operation.textContent, /canonical-sync/);
  assert.match(h.elements.status.textContent, /Sync completed/);
  assert(!h.elements.status.textContent.includes("request completed"));
  h.elements.check.click(); await settle(); assert.equal(h.calls.at(-1)[2], "requested-sync");
  assert.equal(h.timers.size, 0); h.panel.dispose();
});

test("activation dialog shows full immutable source and commit, cancellation performs no write", async () => {
  const h = harness(); h.select();
  h.elements.form.submit("activate"); await settle();
  assert.equal(h.elements.dialog.open, true);
  assert.match(h.elements.details.textContent, /source-a/); assert(h.elements.details.textContent.includes(commit));
  assert(h.elements.form.buttons.every(button => button.disabled));
  h.elements.cancel.click(); assert.equal(h.elements.dialog.open, false); assert.equal(h.calls.length, 0);
  h.elements.form.submit("activate"); await settle(); h.elements.confirm.click(); await settle();
  assert.equal(h.calls[0][0], "activate"); assert.deepEqual(h.calls[0][2], { commit });
  assert.equal(h.elements.dialog.open, false); h.panel.dispose();
});

test("selection or route changes close confirmation and cannot execute the previously shown revision", async () => {
  const h = harness(); h.select(); h.elements.form.submit("activate"); await settle();
  h.select({ selectedRevision: { commit: "b".repeat(40), state: "ready" } });
  assert.equal(h.elements.dialog.open, false); h.elements.confirm.click(); await settle(); assert.equal(h.calls.length, 0);
  h.elements.form.submit("activate"); await settle();
  h.panel.setContext({ route: "run", authenticated: true });
  assert.equal(h.elements.dialog.open, false); h.elements.confirm.click(); await settle();
  assert.equal(h.calls.length, 0); assert.equal(h.elements.check.disabled, true); h.panel.dispose();
});

test("selection updates populate explicit fields once and disposal removes form/control effects", async () => {
  const h = harness(); h.select(); assert.equal(h.elements.fields.sourceId.value, "source-a");
  h.elements.fields.sourceId.value = "edited-source"; h.select();
  assert.equal(h.elements.fields.sourceId.value, "edited-source");
  h.panel.dispose(); h.elements.form.submit("sync"); h.elements.check.click(); await settle();
  assert.equal(h.calls.length, 0); assert.equal(h.timers.size, 0);
});

test("dialog cancellation returns focus to its trigger and confirmed completion focuses its status", async () => {
  const h = harness(); h.select(); h.elements.form.submit("activate"); await settle();
  h.elements.dialog.dispatchEvent(new Event("cancel", { cancelable: true }));
  assert.equal(h.elements.form.buttons[2].focusCalls, 1);
  h.elements.form.submit("activate"); await settle(); h.elements.confirm.click(); await settle();
  assert.equal(h.elements.status.focusCalls, 1); h.panel.dispose();
});
