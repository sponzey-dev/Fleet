/** @file Loopback-only browser QA fixture, never a Fleet runtime or real credential endpoint. */
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
// This public dummy value is fixture data, not a valid Fleet admin token.
const fixtureAuthorization = "Bearer fixture-admin";
const cases = ["long", "slow", "other", "forbidden", "missing", "retry", "unknown", "wide", "large"];
const reads = new Map(cases.map((id) => [id, 0]));
const outputReads = new Map(cases.map((id) => [id, 0]));
const pageReads = new Map(cases.map((id) => [id, 0]));
const catalogReads = { sources: 0, revisions: 0, documents: 0, operations: 0 };
const catalogWrites = { sync: 0, activate: 0 };
const syncOperations = new Map();
const catalogJobs = new Map();
const catalogJobWrites = { create: 0, approve: 0, reject: 0 };
let catalogActiveCommit = "a".repeat(40);
const catalogSourceId = `catalog-${"long-source-".repeat(8)}a`;
const catalogPath = `runbooks/${"nested-component/".repeat(12)}`;
const assets = new Map([
  ["/admin/", ["index.html", "text/html"]],
  ["/admin/index.html", ["index.html", "text/html"]],
  ["/admin/styles.css", ["styles.css", "text/css"]],
  ["/admin/app.js", ["app.js", "application/javascript"]],
  ["/admin/api-client.js", ["api-client.js", "application/javascript"]],
  ["/admin/admin-accounts.js", ["admin-accounts.js", "application/javascript"]],
  ["/admin/job-observer.js", ["job-observer.js", "application/javascript"]],
  ["/admin/job-output-reader.js", ["job-output-reader.js", "application/javascript"]],
  ["/admin/catalog-explorer.js", ["catalog-explorer.js", "application/javascript"]],
  ["/admin/catalog-actions.js", ["catalog-actions.js", "application/javascript"]],
  ["/admin/catalog-job.js", ["catalog-job.js", "application/javascript"]],
]);

function job(id, count = 0) {
  const status = id === "unknown" ? "failed" : id === "long" && count < 52 ? "running" : "success";
  return {
    id: `fixture-${id}`, status, dispatch_state: status === "running" ? "running" : status === "success" ? "completed" : "failed",
    command_program: "fixture-only", command_args: [], target_count: 2,
    last_error: status === "failed" ? "execution_outcome_unknown" : "",
    target_agents: [
      { agent_id: id === "wide" ? `fixture-agent-${"long-name-".repeat(18)}` : "fixture-agent-a", connected: true, status: "online", assignment_status: "succeeded", task_id: `task-${id}-a`, last_error: "" },
      { agent_id: "fixture-agent-b", connected: true, status: "online", assignment_status: status === "running" ? "started" : status === "success" ? "succeeded" : "failed", task_id: `task-${id}-b`, last_error: status === "failed" ? "execution_outcome_unknown" : "" },
    ],
    rendered_artifacts: [],
  };
}

function json(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}

function outputChunks(id) {
  if (id === "large") return Array.from({ length: 320 }, (_, i) => ({
    agent_id: i % 2 === 0 ? "fixture-agent-a" : "fixture-agent-b", stream: i % 2 === 0 ? "stdout" : "stderr",
    sequence: Math.floor(i / 2), data: `Fixture row ${i}: ${"한글-output-".repeat(300)}\n`,
  }));
  return [
    { agent_id: job(id).target_agents[0].agent_id, stream: "stdout", sequence: 0, data: id === "wide" ? `Fixture wide output\n${"한글-wide-output-".repeat(160)}\n` : `Fixture ${id} output\n` },
    { agent_id: "fixture-agent-b", stream: "stderr", sequence: 0, data: Array.from({ length: 80 }, (_, i) => `line ${i}: 한글 output for ${id}`).join("\n") },
  ];
}

// Test-only position format. It deliberately does not emulate the Controller's
// trust/epoch codec: browser callers must keep any returned position opaque.
function outputPage(id, query) {
  const scope = JSON.stringify([id, query.get("agent_id"), query.get("stream")]);
  const limit = Number(query.get("limit") ?? 128), budget = Number(query.get("max_bytes") ?? 65536);
  if (!Number.isInteger(limit) || limit < 1 || limit > 256 || !Number.isInteger(budget) || budget < 4096 || budget > 262144) return null;
  let index = 0, offset = 0;
  if (query.has("after")) {
    const raw = query.get("after");
    if (!raw.startsWith("op1.")) return null;
    try {
      const cursor = JSON.parse(Buffer.from(raw.slice(4), "base64url").toString("utf8"));
      if (cursor.scope !== scope || !Number.isSafeInteger(cursor.index) || !Number.isSafeInteger(cursor.offset) || cursor.index < 0 || cursor.offset < 0) return null;
      index = cursor.index; offset = cursor.offset;
    } catch { return null; }
  }
  const chunks = outputChunks(id).map((chunk, i) => ({ ...chunk, key: String(i + 1) }))
    .filter((chunk) => (!query.has("agent_id") || chunk.agent_id === query.get("agent_id")) && (!query.has("stream") || chunk.stream === query.get("stream")));
  if (index > chunks.length || (index === chunks.length && offset !== 0)) return null;
  const items = []; let used = 0;
  while (index < chunks.length && items.length < limit) {
    const chunk = chunks[index], body = Buffer.from(chunk.data), metadata = Buffer.byteLength(chunk.agent_id + chunk.stream);
    if (offset > body.length || (offset < body.length && (body[offset] & 0xc0) === 0x80)) return null;
    let end = Math.min(body.length, offset + Math.max(0, budget - used - metadata));
    while (end > offset && end < body.length && (body[end] & 0xc0) === 0x80) end -= 1;
    if (metadata > budget - used || (end === offset && end < body.length)) {
      if (!items.length) return { metadataTooLarge: true };
      break;
    }
    items.push({ chunk_key: chunk.key, agent_id: chunk.agent_id, stream: chunk.stream, sequence: String(chunk.sequence),
      offset_bytes: String(offset), total_bytes: String(body.length), data: body.subarray(offset, end).toString("utf8"), chunk_complete: end === body.length });
    used += metadata + end - offset;
    if (end === body.length) { index += 1; offset = 0; } else offset = end;
  }
  return { items, next_after: `op1.${Buffer.from(JSON.stringify({ scope, index, offset })).toString("base64url")}`,
    has_more: index < chunks.length, caught_up: index === chunks.length, history: "tracked", job_status: job(id, reads.get(id)).status };
}

// Catalog Job/approval data below is synthetic process memory. No document is executed.
function catalogJobDetail(entry) {
  const status = entry.status;
  return { id: entry.body.job_id, status, dispatch_state: status === "partial_success" ? "completed" : status,
    command_program: null, command_args: [], risk: "high", selector_kind: "explicit_ids", selector_source: JSON.stringify(entry.body.target_agent_ids),
    target_count: entry.body.target_agent_ids.length, target_agent_ids: entry.body.target_agent_ids,
    target_agents: entry.body.target_agent_ids.map((id,i)=>({agent_id:id,name:`Fixture Agent ${i+1}`,status:i?"offline":"online",connected:!i,
      labels:[],assignment_status:status==="partial_success"?(i?"failed":"succeeded"):status==="canceled"?"canceled":"queued",last_error:status==="partial_success"&&i?"fixture_failure":""})),
    assignment_summary: status === "partial_success" ? {succeeded:1,failed:1} : {queued:entry.body.target_agent_ids.length},
    catalog_provenance: {source_id:entry.body.source_id,commit:entry.body.commit,path:entry.body.path,checksum:entry.body.checksum},
    rendered_artifacts:[],strategy:{concurrency:1,max_failures:null},target_connected:true,created_at_ms:0,updated_at_ms:0,expires_at_ms:null,last_error:"" };
}
function catalogApproval(entry) { return { id:entry.approvalId,job_id:entry.body.job_id,requester:"fixture-operator",approver:entry.status==="pending_approval"?null:"fixture-reviewer",
  reason:"Synthetic browser-only review",status:entry.status==="pending_approval"?"pending":entry.status==="canceled"?"rejected":"approved",expires_at_ms:Date.now()+300000,created_at_ms:0,decided_at_ms:null }; }
async function fixtureBody(request) {
  let body="";for await(const chunk of request){body+=chunk;if(Buffer.byteLength(body)>65536)throw Error("fixture input limit");}return JSON.parse(body);
}
function catalogJobPage(entry, query) {
  const done=entry.status==="partial_success", after=query.get("after"), final=`op1.catalog-${entry.body.job_id}-final`, waiting=`op1.catalog-${entry.body.job_id}-waiting`;
  const items=done&&after!==final?entry.body.target_agent_ids.map((id,i)=>{const data=`Synthetic catalog result for Agent ${i+1}\n`;return {chunk_key:String(i+1),agent_id:id,stream:"stdout",sequence:"0",offset_bytes:"0",total_bytes:String(Buffer.byteLength(data)),data,chunk_complete:true};}):[];
  return {items,next_after:done?final:waiting,has_more:false,caught_up:true,history:"tracked",job_status:entry.status};
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url || "/", "http://127.0.0.1");
  const path = url.pathname;
  if (request.method === "GET" && path === "/favicon.ico") {
    response.writeHead(204);
    response.end();
    return;
  }
  const asset = assets.get(path);
  if (request.method === "GET" && asset) {
    try {
      const content = await readFile(join(root, asset[0]));
      response.writeHead(200, { "Content-Type": `${asset[1]}; charset=utf-8`, "Cache-Control": "no-store" });
      response.end(content);
    } catch { json(response, 500, { error: "fixture_asset_unavailable" }); }
    return;
  }
  if (request.method === "GET" && path === "/api/auth/status") {
    json(response, 200, { mode: "legacy", local_setup_required: false });
    return;
  }
  if (request.headers.authorization !== fixtureAuthorization) {
    json(response, 401, { error: "fixture_unauthorized" });
    return;
  }
  if (request.method === "POST" && path === "/api/selectors/preview") {
    let body;try{body=await fixtureBody(request);}catch{json(response,400,{error:"fixture_invalid_input"});return;}
    if(body.selector?.includes("forbidden")){json(response,403,{error:"fixture_forbidden"});return;}
    const agents=body.selector?.includes("empty")?[]:[
      {agent_id:"fixture-agent-a",name:`Web ${"long-hostname-".repeat(8)}`,status:"online",labels:[],selected_for_dispatch:true},
      {agent_id:"fixture-agent-b",name:"Offline fixture Agent",status:"offline",labels:[],selected_for_dispatch:true},
      {agent_id:"fixture-agent-disabled",name:"Disabled fixture Agent",status:"disabled",labels:[],selected_for_dispatch:false}];
    const value={matched_count:agents.length,selected_count:agents.length?2:0,disabled_count:agents.length?1:0,offline_count:agents.length?1:0,warnings:[],agents};
    if(body.selector?.includes("slow")){const timer=setTimeout(()=>{if(!response.destroyed)json(response,200,value);},12000);response.once("close",()=>clearTimeout(timer));}
    else json(response,200,value);return;
  }
  if (request.method === "POST" && path === "/api/jobs/catalog-runbook") {
    let body;try{body=await fixtureBody(request);}catch{json(response,400,{error:"fixture_invalid_input"});return;}
    catalogJobWrites.create++;
    if(catalogJobs.has(body.job_id)){json(response,409,{error:"job_already_exists"});return;}
    if(body.source_id!==catalogSourceId||body.commit!==catalogActiveCommit||body.checksum!=="c".repeat(64)){json(response,409,{error:"catalog_selection_changed"});return;}
    if("runbook_document"in body||"actor"in body||!Array.isArray(body.target_agent_ids)||!body.target_agent_ids.length){json(response,400,{error:"fixture_invalid_reference"});return;}
    const entry={body,status:"pending_approval",approvalId:`approval-${body.job_id}`};catalogJobs.set(body.job_id,entry);
    json(response,201,{job_id:body.job_id,status:entry.status,target_count:body.target_agent_ids.length,assignment_count:body.target_agent_ids.length,approval_request_id:entry.approvalId});return;
  }
  const decision=path.match(/^\/api\/approvals\/(approval-job-catalog-ui-[^/]+)\/(approve|reject)$/);
  if(request.method==="POST"&&decision){
    request.resume();const entry=[...catalogJobs.values()].find(e=>e.approvalId===decision[1]);
    if(!entry){json(response,404,{error:"fixture_missing_approval"});return;}
    if(entry.status!=="pending_approval"){json(response,409,{error:"fixture_approval_decided"});return;}
    entry.status=decision[2]==="approve"?"partial_success":"canceled";catalogJobWrites[decision[2]]++;
    json(response,200,catalogApproval(entry));return;
  }
  if(request.method==="GET"&&path==="/api/approvals"){json(response,200,[...catalogJobs.values()].filter(e=>e.status==="pending_approval").map(catalogApproval));return;}
  const catalogResult=path.match(/^\/api\/jobs\/(job-catalog-ui-[^/]+)(\/output-page)?$/);
  if(request.method==="GET"&&catalogResult){
    const entry=catalogJobs.get(catalogResult[1]);if(!entry){json(response,404,{error:"fixture_missing_job"});return;}
    json(response,200,catalogResult[2]?catalogJobPage(entry,url.searchParams):catalogJobDetail(entry));return;
  }
  const document=path.match(/^\/api\/catalog\/sources\/([^/]+)\/revisions\/([a-f0-9]+)\/document$/);
  if(request.method==="GET"&&document){
    const selectedPath=url.searchParams.get("path");if(document[1]!==catalogSourceId||!selectedPath?.startsWith(catalogPath)){json(response,404,{error:"fixture_missing_document"});return;}
    json(response,200,{kind:"runbook",path:selectedPath,checksum:"c".repeat(64),body:`# Synthetic browser-only document. Never executed.\napiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: browser-fixture\nselector: role=web\nsteps:\n  - id: collect\n    facts.collect:\n${"# Public fixture review text\n".repeat(100)}`});return;
  }
  // Synthetic Catalog commands change this process's disposable memory only.
  // They never call Fleet, Git, a database, a service or an external authority.
  const command = path.match(/^\/api\/catalog\/sources\/([^/]+)\/(sync|activate)$/);
  if (request.method === "POST" && command && command[1] === catalogSourceId) {
    let body = "";
    for await (const chunk of request) {
      body += chunk;
      if (Buffer.byteLength(body) > 4096) { json(response, 413, { error: "fixture_body_limit" }); return; }
    }
    try { body = JSON.parse(body); } catch { json(response, 400, { error: "fixture_bad_json" }); return; }
    if (command[2] === "sync" && typeof body.operation_id === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(body.operation_id)) {
      const id = `canonical-${body.operation_id}`;
      if (!syncOperations.has(id)) syncOperations.set(id, { reads: 0, input: body.operation_id });
      catalogWrites.sync++;
      json(response, 202, { id, source_id: catalogSourceId, state: "in_progress" }); return;
    }
    if (command[2] === "activate" && typeof body.commit === "string" && /^[a-f0-9]{40}$/.test(body.commit)) {
      catalogWrites.activate++; catalogActiveCommit = body.commit;
      json(response, 200, { id: catalogSourceId, active_commit: body.commit }); return;
    }
    json(response, 400, { error: "fixture_bad_command" }); return;
  }
  if (request.method !== "GET") {
    request.resume();
    json(response, 405, { error: "read_only_browser_fixture" });
    return;
  }
  // Test metadata only: proves that leaving/pausing releases the browser reader.
  if (path === "/__fixture__/observations") {
    json(response, 200, { job_reads: Object.fromEntries(reads), output_reads: Object.fromEntries(outputReads), page_reads: Object.fromEntries(pageReads), catalog_reads: catalogReads, catalog_writes: catalogWrites, catalog_job_writes: catalogJobWrites, catalog_job_count: catalogJobs.size, active_commit: catalogActiveCommit });
    return;
  }
  if (path === "/api/jobs") {
    json(response, 200, [...cases.map((id) => job(id, reads.get(id))), ...[...catalogJobs.values()].map(catalogJobDetail)]);
    return;
  }
  const selected = path.match(/^\/api\/jobs\/fixture-([a-z]+)(\/output(?:-page)?)?$/);
  if (selected && reads.has(selected[1])) {
    const [, id, output] = selected;
    if (id === "forbidden") { json(response, 403, { error: "fixture_forbidden" }); return; }
    if (id === "missing") { json(response, 404, { error: "fixture_missing" }); return; }
    if (output === "/output-page") {
      pageReads.set(id, pageReads.get(id) + 1);
      const page = outputPage(id, url.searchParams);
      if (!page) json(response, 400, { error: "fixture_invalid_position" });
      else if (page.metadataTooLarge) json(response, 413, { error: "fixture_metadata_too_large" });
      else json(response, 200, page);
      return;
    }
    if (output) {
      outputReads.set(id, outputReads.get(id) + 1);
      json(response, 200, outputChunks(id));
      return;
    }
    const count = reads.get(id) + 1;
    reads.set(id, count);
    if (id === "retry" && count < 3) { json(response, 503, { error: "fixture_transient" }); return; }
    if (id === "slow") {
      const timer = setTimeout(() => { if (!response.destroyed) json(response, 200, job(id, count)); }, 5000);
      response.once("close", () => clearTimeout(timer));
    } else json(response, 200, job(id, count));
    return;
  }
  const emptyLists = ["/api/agents", "/api/enrollment-tokens", "/api/approvals", "/api/policies", "/api/remediations"];
  if (emptyLists.includes(path)) { json(response, 200, []); return; }
  const syncStatus = path.match(/^\/api\/catalog\/sources\/([^/]+)\/sync-operations\/([^/]+)$/);
  if (syncStatus) {
    catalogReads.operations++;
    const entry = syncOperations.get(syncStatus[2]);
    if (!entry || syncStatus[1] !== catalogSourceId) { json(response, 404, { error: "fixture_missing_operation" }); return; }
    entry.reads++;
    const state = entry.reads < 3 ? "in_progress" : entry.input.includes("fail") ? "failed" : entry.input.includes("cancel") ? "cancelled" : "completed";
    const result = { id: syncStatus[2], source_id: catalogSourceId, state,
      commit: state === "completed" ? "b".repeat(40) : null, failure: state === "failed" ? "fetch_failed" : null };
    if (entry.input.includes("slow")) {
      const timer = setTimeout(() => { if (!response.destroyed) json(response, 200, result); }, 5000);
      response.once("close", () => clearTimeout(timer));
    } else json(response, 200, result);
    return;
  }
  if (path === "/api/catalog/sources") {
    catalogReads.sources++;
    const after = url.searchParams.get("after");
    const ids = after ? ["zeta-forbidden"] : [catalogSourceId, ...Array.from({ length: 49 }, (_, i) => `source-${String(i).padStart(3, "0")}`)];
    json(response, 200, { items: ids.map(id => ({ id, url: "https://example.com/fixture-catalog.git", reference: "main", active_commit: catalogActiveCommit })),
      next_after: after ? null : ids.at(-1) }); return;
  }
  const catalog = path.match(/^\/api\/catalog\/sources\/([^/]+)\/revisions(?:\/([a-f0-9]+)\/documents)?$/);
  if (catalog) {
    const documents = Boolean(catalog[2]); catalogReads[documents ? "documents" : "revisions"]++;
    if (decodeURIComponent(catalog[1]) === "zeta-forbidden") { json(response, 403, { error: "fixture_forbidden" }); return; }
    const after = url.searchParams.get("after");
    const items = documents
      ? (after ? ["z"] : Array.from({ length: 50 }, (_, i) => String(i).padStart(3, "0"))).map(key => ({ kind: "runbook", path: `${catalogPath}${key}.yaml`, checksum: "c".repeat(64) }))
      : (after ? ["b".repeat(40)] : Array.from({ length: 50 }, (_, i) => (BigInt(`0x${"a".repeat(40)}`) + BigInt(i)).toString(16))).map(commit => ({ commit, state: "ready", document_count: 50, failure: null }));
    json(response, 200, { items, next_after: after ? null : documents ? items.at(-1).path : items.at(-1).commit }); return;
  }
  if (path === "/api/audit/export") { json(response, 200, { items: [], next_cursor: null }); return; }
  if (path === "/api/controller/signing-rotation/status") { json(response, 200, {}); return; }
  json(response, 404, { error: "fixture_route_not_found" });
});
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.listen(17701, "127.0.0.1", () => {
  console.log("Synthetic browser fixture (Catalog writes are memory-only): http://127.0.0.1:17701/admin/#run (dummy token: fixture-admin)");
});
// One owned, bounded fixture lifetime; no background service or persisted data.
const deadline = setTimeout(() => server.close(), 20 * 60 * 1000);
server.once("close", () => clearTimeout(deadline));
for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => server.close());
