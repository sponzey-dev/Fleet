import test from "node:test";
import assert from "node:assert/strict";
import { createCatalogJobSubmission } from "../catalog-job.js";

const commit = "a".repeat(40), checksum = "c".repeat(64);
const reference = () => ({ sourceId: "source-a", commit, path: "runbooks/safe.yaml", checksum, state: "ready", activeCommit: commit, kind: "runbook", stale: false });
const context = (selection = reference()) => ({ route: "runbooks", authenticated: true, selection });
const detail = () => ({ kind: "runbook", path: "runbooks/safe.yaml", checksum, body: "public Runbook source" });
const preview = () => ({ matched_count: 2, selected_count: 1, disabled_count: 1, offline_count: 1, warnings: [], agents: [
  { agent_id: "offline-a", name: "Offline A", status: "offline", labels: [], selected_for_dispatch: true },
  { agent_id: "disabled-a", name: "Disabled A", status: "disabled", labels: [], selected_for_dispatch: false },
] });
const created = () => ({ job_id: "job-a", target_count: 1, assignment_count: 1, status: "pending_approval", approval_request_id: "approval-a" });
const stored = () => ({ id: "job-a", status: "pending_approval", target_agent_ids: ["offline-a"], catalog_provenance: { source_id: "source-a", commit, path: "runbooks/safe.yaml", checksum } });
const settle = async () => { for (let i=0;i<30;i++) await Promise.resolve(); };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve=r; }); return { promise, resolve }; };
function harness(overrides = {}) {
  const calls=[], events=[], timers=new Map();let timer=0;
  const api={
    getCatalogDocumentDetail(...args) {calls.push(["detail",...args]);return overrides.detail?.(...args) ?? detail();},
    previewSelector(...args) {calls.push(["preview",...args]);return overrides.preview?.(...args) ?? preview();},
    createCatalogRunbookJob(...args) {calls.push(["create",...args]);return overrides.create?.(...args) ?? created();},
    getJob(...args) {calls.push(["job",...args]);return overrides.job?.(...args) ?? stored();},
  };
  const clock={setTimeout(fn,ms){timers.set(++timer,{fn,ms});return timer;},clearTimeout(id){timers.delete(id);}};
  const owner=createCatalogJobSubmission({api,clock,makeJobId:()=>"job-a",onChange:overrides.onChange,onCreated:job=>{events.push(job);overrides.onCreated?.(job);}});
  owner.setContext(context());owner.setSelector("role=web");
  return {owner,calls,events,timers,timeout:async()=>{for(const [id,t]of [...timers]){timers.delete(id);t.fn();}await settle();}};
}

test("catalog Job uses the inspected durable reference and previewed IDs, retaining approval and no body override", async()=>{
  const h=harness();await h.owner.preview();
  assert.equal(h.owner.getSnapshot().phase,"prepared");
  await h.owner.submit();assert.equal(h.calls.filter(c=>c[0]==="create").length,0,"confirmation required");
  h.owner.setConfirmed(true);await h.owner.submit();await h.owner.submit();
  const requests=h.calls.filter(c=>c[0]==="create");assert.equal(requests.length,1);
  assert.deepEqual(requests[0][1],{job_id:"job-a",source_id:"source-a",commit,path:"runbooks/safe.yaml",checksum,target_agent_ids:["offline-a"],timeout_seconds:30,expires_in_seconds:300,confirmed_high_risk:true});
  assert.equal(h.owner.getSnapshot().phase,"created");assert.equal(h.events.length,1);assert.equal(h.events[0].approval_request_id,"approval-a");
  assert.equal(h.timers.size,0);h.owner.dispose();
});

test("catalog Job accepts known inventory states without changing the reviewed dispatch IDs", async()=>{
  const agents=["pending","busy","degraded","disabled"].map(status=>({agent_id:`agent-${status}`,name:status,status,labels:[],selected_for_dispatch:status!=="disabled"}));
  const h=harness({preview:()=>({matched_count:4,selected_count:3,disabled_count:1,offline_count:0,warnings:[],agents})});
  await h.owner.preview();
  assert.equal(h.owner.getSnapshot().phase,"prepared");
  assert.deepEqual(h.owner.getSnapshot().preview.ids,["agent-pending","agent-busy","agent-degraded"]);
  assert.equal(h.calls.filter(c=>c[0]==="create").length,0);
  h.owner.dispose();
});

test("catalog Job retires a definitively rejected selection and permits a fresh explicit review",async()=>{
  const h=harness({create:()=>{throw Object.assign(new Error("safe rejection"),{status:409,catalogRejected:true});}});
  await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();
  assert.equal(h.owner.getSnapshot().phase,"error");
  assert.equal(h.owner.getSnapshot().jobId,"");
  assert.equal(h.calls.filter(c=>c[0]==="create").length,1);
  const next={...reference(),commit:"b".repeat(40),activeCommit:"b".repeat(40)};
  h.owner.setContext(context(next));await h.owner.preview();
  assert.equal(h.owner.getSnapshot().phase,"prepared");
  assert.equal(h.calls.filter(c=>c[0]==="create").length,1,"new review does not submit");h.owner.dispose();
});

test("a missing uncertain Job can retry its original immutable request after the current selection changes",async()=>{
  let attempts=0;
  const h=harness({create:()=>{if(++attempts===1)throw new Error("network");throw Object.assign(new Error("stale original"),{status:409,catalogRejected:true});},job:()=>{throw Object.assign(new Error("missing"),{status:404});}});
  await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();
  h.owner.setContext(context({...reference(),commit:"b".repeat(40),activeCommit:"b".repeat(40)}));
  await h.owner.reconcile();assert.equal(h.owner.getSnapshot().phase,"missing");
  assert.equal(h.owner.getSnapshot().canRetry,true);
  assert.equal(attempts,1,"context and reconciliation never POST");
  await h.owner.retry();
  const requests=h.calls.filter(c=>c[0]==="create");assert.equal(requests.length,2);assert.deepEqual(requests[0][1],requests[1][1]);
  assert.equal(h.owner.getSnapshot().phase,"error");assert.equal(h.owner.getSnapshot().jobId,"");h.owner.dispose();
});

test("catalog Job rejects nonactive, stale, wrong-kind and inactive-route selections before reading", async()=>{
  for(const next of [context({...reference(),activeCommit:"b".repeat(40)}),context({...reference(),stale:true}),context({...reference(),kind:"policy"}),context({...reference(),state:"failed"}),{...context(),route:"policies"},{...context(),authenticated:false}]){
    const h=harness();h.owner.setContext(next);await h.owner.preview();assert.equal(h.calls.length,0);assert.equal(h.owner.getSnapshot().canSubmit,false);h.owner.dispose();
  }
});

test("catalog Job aborts retired document/preview reads and suppresses late body or target selection", async()=>{
  for(const stage of ["detail","preview"]){
    const wait=deferred();const h=harness({[stage]:()=>wait.promise});const pending=h.owner.preview();await settle();
    const call=h.calls.find(c=>c[0]===stage);const signal=call.at(-1).signal;
    h.owner.setSelector("role=database");assert(signal.aborted);await pending;
    wait.resolve(stage==="detail"?detail():preview());await settle();
    assert.notEqual(h.owner.getSnapshot().phase,"prepared");assert.equal(h.owner.getSnapshot().body,"");assert.equal(h.timers.size,0);h.owner.dispose();
  }
});

test("catalog Job deadline and duplicate click keep one stable unknown intent and never automatically repeat POST", async()=>{
  const wait=deferred();const h=harness({create:()=>wait.promise});await h.owner.preview();h.owner.setConfirmed(true);
  const first=h.owner.submit();await settle();await h.owner.submit();await h.timeout();await first;
  assert.equal(h.owner.getSnapshot().phase,"unknown");assert.equal(h.owner.getSnapshot().jobId,"job-a");
  h.owner.setContext({...context(),route:"overview"});h.owner.setContext(context());await h.owner.submit();
  assert.equal(h.calls.filter(c=>c[0]==="create").length,1);assert.equal(h.events.length,0);
  wait.resolve(created());await settle();assert.equal(h.events.length,0);
  await h.owner.reconcile();assert.equal(h.owner.getSnapshot().phase,"created");assert.equal(h.events.length,1);assert.equal(h.calls.filter(c=>c[0]==="create").length,1);h.owner.dispose();
});

test("catalog Job malformed detail, oversized body and inconsistent target preview never become executable", async()=>{
  for(const overrides of [{detail:()=>({...detail(),checksum:"d".repeat(64)})},{detail:()=>({...detail(),body:"x".repeat(1048577)})},{preview:()=>({...preview(),selected_count:2})},{preview:()=>({...preview(),agents:[...preview().agents,preview().agents[0]]})}]){
    const h=harness(overrides);await h.owner.preview();assert.notEqual(h.owner.getSnapshot().phase,"prepared");h.owner.setConfirmed(true);await h.owner.submit();assert.equal(h.calls.filter(c=>c[0]==="create").length,0);h.owner.dispose();
  }
});

test("catalog Job reconciles only matching immutable provenance and target IDs",async()=>{
  for(const job of [{...stored(),catalog_provenance:{...stored().catalog_provenance,commit:"b".repeat(40)}},{...stored(),target_agent_ids:["other"]}]){
    const h=harness({create:()=>Promise.reject(new TypeError("private failure")),job:()=>job});await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();await h.owner.reconcile();
    assert.notEqual(h.owner.getSnapshot().phase,"created");assert.equal(h.events.length,0);assert(!h.owner.getSnapshot().message.includes("private"));h.owner.dispose();
  }
});

test("catalog Job publishes its busy guard before a render callback can request another preview",async()=>{
  let owner,repeat=false;
  const h=harness({onChange:view=>{if(view.phase==="reading"&&!repeat){repeat=true;void owner.preview();}}});owner=h.owner;
  await owner.preview();await settle();
  assert.equal(h.calls.filter(c=>c[0]==="detail").length,1);assert.equal(h.calls.filter(c=>c[0]==="preview").length,1);owner.dispose();
});

test("catalog Job keeps a verified creation when its results-view callback fails",async()=>{
  const h=harness({onCreated:()=>{throw Error("view failure");}});await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();
  assert.equal(h.owner.getSnapshot().phase,"created");await h.owner.submit();assert.equal(h.calls.filter(c=>c[0]==="create").length,1);h.owner.dispose();
});

test("catalog Job manual retry after a missing reconciliation keeps the exact original ID and snapshot",async()=>{
  let attempts=0;const h=harness({create:()=>++attempts===1?Promise.reject(new TypeError("offline")):created(),job:()=>Promise.reject(Object.assign(new Error("not found"),{status:404}))});
  await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();await h.owner.retry();assert.equal(attempts,1,"must reconcile first");
  await h.owner.reconcile();assert.equal(h.owner.getSnapshot().canRetry,true);await h.owner.retry();
  assert.equal(attempts,2);const bodies=h.calls.filter(c=>c[0]==="create").map(c=>c[1]);assert.deepEqual(bodies[0],bodies[1]);assert.equal(h.owner.getSnapshot().phase,"created");h.owner.dispose();
});

test("catalog Job render failure retires the owner before a POST effect starts",async()=>{
  const h=harness({onChange:view=>{if(view.phase==="submitting")throw Error("view unavailable");}});
  await h.owner.preview();h.owner.setConfirmed(true);await h.owner.submit();
  assert.equal(h.calls.filter(c=>c[0]==="create").length,0);assert.equal(h.timers.size,0);h.owner.dispose();
});

test("an uncertain Job remains queryable but cannot be replayed by the next identity",async()=>{
  const pending=deferred();const h=harness({create:()=>pending.promise,job:()=>{throw {status:404};}});
  h.owner.setContext({...context(),authGeneration:1});
  h.owner.setSelector("role=web");await h.owner.preview();h.owner.setConfirmed(true);
  const submitting=h.owner.submit();await settle();
  h.owner.setContext({...context(),authGeneration:2});
  pending.resolve(created());await submitting;await settle();
  assert.equal(h.owner.getSnapshot().jobId,"job-a","keep the accepted/uncertain identifier for a read");
  assert.equal(h.events.length,0,"an old success cannot publish under B");
  await h.owner.reconcile();await h.owner.retry();
  assert.equal(h.calls.filter(call=>call[0]==="create").length,1);
  assert.equal(h.owner.getSnapshot().canRetry,false);
  assert.equal(h.timers.size,0);h.owner.dispose();
});
