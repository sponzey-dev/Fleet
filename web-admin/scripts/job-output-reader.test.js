/** @file Exact stored-output consumption and bounded display contracts, without a Controller or DOM. */
import assert from "node:assert/strict";
import test from "node:test";
import { createJobOutputReader, OUTPUT_WINDOW_BYTES, OUTPUT_WINDOW_FRAGMENTS, OutputReadError } from "../job-output-reader.js";
import { ApiHttpError } from "../api-client.js";

const bytes = (s) => new TextEncoder().encode(s).length;
function fragment({ key = "1", agent = "a", stream = "stdout", sequence = "0", offset = "0", data = "x", total = String(bytes(data)) } = {}) {
  return { chunk_key: key, agent_id: agent, stream, sequence, offset_bytes: offset, total_bytes: total, data,
    chunk_complete: BigInt(offset) + BigInt(bytes(data)) === BigInt(total) };
}
function page(items = [], { cursor = "op1.c1", more = false, caught = !more, history = "tracked", status = "running" } = {}) {
  return { items, next_after: cursor, has_more: more, caught_up: caught, history, job_status: status };
}
function harness(pages) {
  const calls = [];
  const reader = createJobOutputReader({ api: { getJobOutputPage: async (id, options) => {
    calls.push({ id, options }); const value = pages.shift();
    if (value instanceof Error) throw value;
    assert(value, "unexpected output read"); return value;
  } } });
  reader.reset("job-1");
  return { reader, calls, signal: new AbortController().signal };
}

test("late sequences and interleaved Agents preserve append cursor while displaying canonical stream order", async () => {
  const { reader, calls, signal } = harness([
    page([fragment({ key: "10", agent: "b", sequence: "1", data: "b1" })], { cursor: "op1.first", more: true }),
    page([fragment({ key: "13", agent: "a", stream: "stderr", data: "aerr" })], { cursor: "op1.second", caught: false }),
    page([fragment({ key: "17", agent: "b", sequence: "0", data: "b0" })], { cursor: "op1.third" }),
  ]);
  const result = await reader.read("job-1", { signal });
  assert.equal(result.pages, 3); assert.equal(result.added, 3); assert.equal(result.caughtUp, true);
  assert.deepEqual(calls.map((c) => c.options.after), [undefined, "op1.first", "op1.second"]);
  assert(result.text.indexOf("b0") < result.text.indexOf("b1"));
  assert(!result.text.includes("not present"));
  assert.equal(result.fragments.map((f) => f.data).sort().join("|"), "aerr|b0|b1");
});

test("one read yields after four pages and keeps the exact signal and immutable filter scope", async () => {
  const pages = Array.from({ length: 5 }, (_, i) => page([fragment({ key: String(i + 1), sequence: String(i), data: String(i) })], { cursor: `op1.c${i + 1}`, more: i < 4 }));
  const { reader, calls, signal } = harness(pages);
  reader.reset("job-1", { agentId: "a", stream: "stdout" });
  const first = await reader.read("job-1", { signal });
  assert.equal(first.pages, 4); assert.equal(first.hasMore, true); assert.equal(first.caughtUp, false);
  assert.equal(calls.length, 4);
  for (const { options } of calls) {
    assert.equal(options.signal, signal); assert.equal(options.agentId, "a");
    assert.equal(options.limit, 128); assert.equal(options.maxBytes, 65536);
  }
  const last = await reader.read("job-1", { signal });
  assert.equal(last.pages, 1); assert.equal(last.fragments.length, 5); assert.equal(last.startedOpen, false);
});

test("UTF-8 fragments including NUL and combining characters reassemble without Number coercion", async () => {
  const key = "9007199254740993", sequence = "9007199254740994";
  const a = "한🤖\0", b = "e\u0301\n"; const total = String(bytes(a + b));
  const { reader, signal } = harness([
    page([fragment({ key, sequence, data: a, total })], { cursor: "op1.a", more: true }),
    page([fragment({ key, sequence, offset: String(bytes(a)), data: b, total })], { cursor: "op1.b" }),
  ]);
  const result = await reader.read("job-1", { signal });
  assert.equal(result.fragments.map((f) => f.data).join(""), a + b);
  assert.equal(result.fragments[0].sequence, sequence); assert.equal(result.fragments[0].chunk_key, key);
  assert(result.text.includes(a + b));
});

test("exact duplicate retry is idempotent but a conflicting body does not replace the accepted window", async () => {
  const f = fragment({ data: "original" });
  const { reader, signal } = harness([
    page([f], { cursor: "op1.first" }), page([f], { cursor: "op1.same" }),
    page([fragment({ data: "changed!" })], { cursor: "op1.bad" }),
  ]);
  await reader.read("job-1", { signal });
  const duplicate = await reader.read("job-1", { signal });
  assert.equal(duplicate.added, 0); assert.equal(duplicate.fragments.length, 1);
  await assert.rejects(reader.read("job-1", { signal }), (error) => error instanceof OutputReadError && error.kind === "conflict");
  assert.equal(reader.getSnapshot().fragments[0].data, "original");
});

test("offset gaps and invalid page bodies fail atomically instead of becoming empty success", async () => {
  const { reader, signal } = harness([
    page([fragment({ data: "a", total: "4" })], { more: true }),
    page([fragment({ offset: "2", data: "cd", total: "4" })]),
  ]);
  await assert.rejects(reader.read("job-1", { signal }), (error) => error instanceof OutputReadError && error.kind === "gap");
  assert.equal(reader.getSnapshot().fragments.length, 1);
  for (const bad of [null, {}, page([], { more: true }), page([], { cursor: "" }), page([fragment({ data: "\ud800" })]),
    page([{ ...fragment(), sequence: 1 }]), page([{ ...fragment(), offset_bytes: "00" }]),
    page([{ ...fragment(), total_bytes: "9223372036854775808" }]), page([{ ...fragment(), extra: true }]),
    { ...page(), has_more: true, caught_up: true }, { ...page(), items: Array(129).fill(fragment()) }]) {
    const api = { getJobOutputPage: async () => bad };
    const r = createJobOutputReader({ api }); r.reset("job-1");
    await assert.rejects(r.read("job-1", { signal }), OutputReadError);
    assert.equal(r.getSnapshot().fragments.length, 0);
  }
});

test("byte window evicts old fragments, keeps current text and does not assemble an oversized row", async () => {
  const data = "한".repeat(20000); const total = String(bytes(data) * 30);
  const pages = Array.from({ length: 30 }, (_, i) => page([fragment({ data, total, offset: String(i * bytes(data)) })], { cursor: `op1.c${i}`, more: i < 29 }));
  const { reader, signal } = harness(pages);
  let result;
  for (let i = 0; i < 8; i += 1) result = await reader.read("job-1", { signal });
  assert.equal(result.caughtUp, true); assert.equal(result.trimmed, true);
  assert(bytes(result.text) <= OUTPUT_WINDOW_BYTES);
  assert(result.fragments.length < 30); assert(result.fragments.length <= OUTPUT_WINDOW_FRAGMENTS);
  assert.equal(result.fragments.at(-1).offset_bytes, String(29 * bytes(data)));
  assert(result.text.includes("outside this view"));
});

test("count window is bounded for empty rows and history pages replace rather than accumulate", async () => {
  const pages = Array.from({ length: 18 }, (_, p) => page(Array.from({ length: 128 }, (_, j) => fragment({
    key: String(p * 128 + j + 1), sequence: String(p * 128 + j), data: "",
  })), { cursor: `op1.page${p}`, more: p < 17 }));
  const { reader, signal } = harness(pages);
  let result;
  for (let i = 0; i < 5; i += 1) result = await reader.read("job-1", { signal });
  assert.equal(result.fragments.length, OUTPUT_WINDOW_FRAGMENTS); assert.equal(result.trimmed, true);
  pages.push(page([fragment({ key: "1", data: "" })], { cursor: "op1.old" }));
  await assert.rejects(reader.read("job-1", { signal }), (error) => error instanceof OutputReadError && error.kind === "conflict");
  assert.equal(reader.getSnapshot().fragments.length, OUTPUT_WINDOW_FRAGMENTS);
  const h = harness([page([fragment({ data: "old" })], { more: true, cursor: "op1.first", history: "unknown" }),
    page([fragment({ key: "3", sequence: "1", data: "next" })], { history: "unknown", cursor: "op1.next" })]);
  const first = await h.reader.readHistoryPage("job-1", { signal: h.signal });
  assert.equal(first.pages, 1); assert.equal(first.history, "unknown");
  const second = await h.reader.readHistoryPage("job-1", { signal: h.signal });
  assert.equal(second.fragments.length, 1); assert.equal(second.fragments[0].data, "next");
  assert(second.text.includes("unknown")); assert(!second.text.includes("old"));
});

test("reset, scope changes, disposal and abort prevent late writes to the active window", async () => {
  let resolve;
  const calls = [];
  const reader = createJobOutputReader({ api: { getJobOutputPage: (id, options) => {
    calls.push({ id, options }); return new Promise((yes) => { resolve = yes; });
  } } });
  reader.reset("job-1"); const abort = new AbortController();
  const pending = reader.read("job-1", { signal: abort.signal });
  const check = assert.rejects(pending, (error) => error.name === "AbortError");
  reader.reset("job-2", { agentId: "other" }); abort.abort();
  resolve(page([fragment({ data: "retired" })])); await check;
  assert.equal(reader.getSnapshot().fragments.length, 0);
  const already = new AbortController(); already.abort();
  await assert.rejects(reader.read("job-2", { signal: already.signal }), (error) => error === already.signal.reason);
  assert.equal(calls.length, 1);
  reader.dispose(); assert.equal(reader.getSnapshot().text, "");
});

test("stale or failed reads propagate without legacy fallback or cursor persistence", async () => {
  for (const status of [400, 401, 403, 404, 409, 413, 500]) {
    let legacy = 0;
    const error = new ApiHttpError("safe", status);
    const reader = createJobOutputReader({ api: { getJobOutputPage: async () => { throw error; }, getJobOutput: async () => { legacy += 1; return []; } } });
    reader.reset("job-1");
    await assert.rejects(reader.read("job-1", { signal: new AbortController().signal }), (value) => value === error);
    assert.equal(legacy, 0); assert.equal(reader.getSnapshot().history, null);
  }
});

test("fragment stream must be a JSON string, not a coerced array", async () => {
  const { reader, signal } = harness([page([{ ...fragment(), stream: ["stdout"] }])]);
  await assert.rejects(reader.read("job-1", { signal }), OutputReadError);
  assert.equal(reader.getSnapshot().fragments.length, 0);
});

test("source-byte overflow rejects the whole page before committing any fragment", async () => {
  for (const items of [[fragment({ data: "x".repeat(65537) })], [fragment({ agent: "a".repeat(65536), data: "" })],
    Array.from({ length: 128 }, (_, i) => fragment({ key: String(i + 1), sequence: String(i), data: "x".repeat(512) }))]) {
    const { reader, signal } = harness([page(items)]);
    await assert.rejects(reader.read("job-1", { signal }), OutputReadError);
    assert.equal(reader.getSnapshot().fragments.length, 0);
  }
});

test("nonprogressing cursor and changed history stop without replacing accepted context", async () => {
  for (const bad of [page([fragment()], { cursor: "op1.first", more: true }),
    page([fragment({ key: "2", sequence: "1" })], { cursor: "op1.second", history: "pruned" })]) {
    const { reader, signal } = harness([page([fragment()], { cursor: "op1.first", more: true }), bad]);
    await assert.rejects(reader.read("job-1", { signal }), OutputReadError);
    assert.equal(reader.getSnapshot().fragments.length, 1);
    assert.equal(reader.getSnapshot().history, "tracked");
  }
});

test("abort releases the reader immediately even when a page API ignores its signal", async () => {
  let resolve; let calls = 0;
  const reader = createJobOutputReader({ api: { getJobOutputPage: async () => {
    calls += 1;
    return calls === 1 ? new Promise((yes) => { resolve = yes; }) : page([fragment({ data: "new" })]);
  } } });
  reader.reset("job-1"); const first = new AbortController(); let rejected = false;
  const pending = reader.read("job-1", { signal: first.signal }).catch((error) => { rejected = error === first.signal.reason; });
  first.abort();
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
  try {
    assert.equal(rejected, true, "cancellation must not wait for an uncooperative page promise");
    const result = await reader.read("job-1", { signal: new AbortController().signal });
    assert.equal(result.fragments[0].data, "new");
  } finally {
    resolve(page([fragment({ data: "retired" })])); await pending;
  }
  assert.equal(reader.getSnapshot().fragments[0].data, "new");
});

test("a conflict within one page commits neither its first item nor a new cursor", async () => {
  const { reader, signal, calls } = harness([
    page([fragment({ data: "a" }), fragment({ key: "2", data: "b" })]),
    page([fragment({ data: "valid" })]),
  ]);
  await assert.rejects(reader.read("job-1", { signal }), (error) => error.kind === "conflict");
  assert.equal(reader.getSnapshot().fragments.length, 0);
  const result = await reader.read("job-1", { signal });
  assert.equal(calls[1].options.after, undefined); assert.equal(result.fragments[0].data, "valid");
});
