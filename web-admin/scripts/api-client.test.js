import assert from "node:assert/strict";
import test from "node:test";
import { createApiClient } from "../api-client.js";

test("personal token metadata and revocation keep scoped cursors private and DELETE body-free",async()=>{
  const calls=[],controller=new AbortController();let status=200,reads=0;
  const client=createApiClient({tokenProvider:()=>{throw new Error("must not discover a bearer");},fetchImpl:async(path,options)=>{
    calls.push({path,options});return {ok:status<300,status,json:async()=>{reads++;return {items:[],next_cursor:null};}};
  }});
  const cursor="private scoped position +/=";
  await client.getAdminPersonalTokens({after:cursor,limit:0,signal:controller.signal});
  const url=new URL(calls[0].path,"https://fixture.invalid");
  assert.equal(url.pathname,"/api/auth/tokens");assert.equal(url.searchParams.get("after"),cursor);assert.equal(url.searchParams.get("limit"),"0");
  status=204;
  assert.equal(await client.revokeAdminPersonalToken("crd_a/b",{csrfToken:"fixture-csrf",signal:controller.signal}),null);
  assert.equal(calls[1].path,"/api/auth/tokens/crd_a%2Fb");assert.equal(calls[1].options.method,"DELETE");
  assert(!calls[1].options.body);assert.equal(calls[1].options.headers["X-Fleet-CSRF"],"fixture-csrf");
  for(const call of calls){
    assert(!Object.hasOwn(call.options.headers,"Authorization"));assert.equal(call.options.credentials,"same-origin");
    assert.equal(call.options.cache,"no-store");assert.equal(call.options.signal,controller.signal);
  }
  for(status of [401,403,404,409,503]){
    for(const action of [()=>client.getAdminPersonalTokens({after:cursor}),()=>client.revokeAdminPersonalToken("private-id")]){
      const before=calls.length;
      await assert.rejects(action(),error=>error.status===status&&!error.message.includes(cursor)&&!error.message.includes("private-id")&&!error.message.includes("after="));
      assert.equal(calls.length,before+1);
    }
  }
  assert.equal(reads,1,"error bodies and successful DELETE bodies are never read");
  controller.abort();const before=calls.length;
  await assert.rejects(client.revokeAdminPersonalToken("fixture",{signal:controller.signal}),error=>error===controller.signal.reason);
  assert.equal(calls.length,before);
});

test("self password and token effects remain cookie-only, cancellable single requests without retaining proof",async()=>{
  const calls=[],controller=new AbortController();let status=204;
  const client=createApiClient({tokenProvider:()=>{throw new Error("must not discover a bearer");},fetchImpl:async(path,options)=>{
    calls.push({path,options});return {ok:status<300,status,json:async()=>({token:{id:"fixture",expires_at:123,secret:"once-only"}})};
  }});
  const options={csrfToken:"fixture-csrf",signal:controller.signal};
  const password={current_password:"private previous",new_password:"private next"};
  assert.equal(await client.changeOwnAdminPassword(password,options),null);
  status=201;
  const token={current_password:"private previous",label:"Fixture laptop"};
  assert.equal((await client.createAdminPersonalToken(token,options)).token.secret,"once-only");
  assert.deepEqual(calls.map(call=>[call.path,call.options.method]),[["/api/auth/password","POST"],["/api/auth/tokens","POST"]]);
  assert.deepEqual(calls.map(call=>JSON.parse(call.options.body)),[password,token]);
  for(const call of calls){
    assert.equal(call.options.headers["X-Fleet-CSRF"],options.csrfToken);assert(!Object.hasOwn(call.options.headers,"Authorization"));
    assert.equal(call.options.signal,controller.signal);assert.equal(call.options.credentials,"same-origin");assert.equal(call.options.cache,"no-store");
  }
  for(status of [401,403,404,409,429,503]){
    const before=calls.length;
    await assert.rejects(client.createAdminPersonalToken(token,options),error=>error.status===status&&!error.message.includes(token.current_password));
    assert.equal(calls.length,before+1);
  }
  controller.abort();const before=calls.length;
  await assert.rejects(client.changeOwnAdminPassword(password,options),error=>error===controller.signal.reason);
  assert.equal(calls.length,before);
});

test("owner mutations use one cookie/CSRF request, exact verbs and safe diagnostics without retry",async()=>{
  const calls=[],controller=new AbortController();let status=201,reads=0;
  const client=createApiClient({tokenProvider:()=>{throw new Error("must not discover bearer");},fetchImpl:async(path,options)=>{
    calls.push({path,options});return {ok:status<300,status,json:async()=>{reads++;return {user:{id:"fixture"}};}};
  }});
  const options={csrfToken:"fixture-csrf",signal:controller.signal};
  const body={current_password:"private current password",display_name:"Fixture"};
  await client.createAdminUser(body,options);
  await client.changeAdminUser("usr_a/b",body,options);
  await client.resetAdminUserPassword("usr_a/b",body,options);
  assert.deepEqual(calls.map(call=>[call.path,call.options.method]),[
    ["/api/admin/users","POST"],["/api/admin/users/usr_a%2Fb","PATCH"],["/api/admin/users/usr_a%2Fb/password-reset","POST"],
  ]);
  for(const call of calls){
    assert.equal(call.options.credentials,"same-origin");assert.equal(call.options.cache,"no-store");
    assert(!Object.hasOwn(call.options.headers,"Authorization"));assert.equal(call.options.headers["X-Fleet-CSRF"],options.csrfToken);
    assert.equal(call.options.signal,controller.signal);assert.deepEqual(JSON.parse(call.options.body),body);
  }
  for(status of [401,403,404,409,429,503]){
    const before=calls.length;
    await assert.rejects(client.resetAdminUserPassword("private-id",body,options),error=>error.status===status&&!error.message.includes("private-id")&&!error.message.includes(body.current_password));
    assert.equal(calls.length,before+1,"uncertain mutations never retry automatically");
  }
  assert.equal(reads,3,"private error bodies are not read");
  controller.abort();const before=calls.length;
  await assert.rejects(client.changeAdminUser("fixture",body,options),error=>error===controller.signal.reason);
  assert.equal(calls.length,before);
});

test("owner metadata effects require endpoints and keep opaque cursors out of diagnostics",async()=>{
  const calls=[],controller=new AbortController();let status=200;
  const client=createApiClient({tokenProvider:()=>{throw new Error("cookie metadata must not discover bearer credentials");},fetchImpl:async(path,options)=>{
    calls.push({path,options});return {ok:status===200,status,json:async()=>({items:[]})};
  }});
  const opaque="opaque owner position +/=";
  await client.getAdminUsers({limit:0,after:opaque,signal:controller.signal});
  const url=new URL(calls[0].path,"https://fixture.invalid");
  assert.equal(url.pathname,"/api/admin/users");
  assert.equal(url.searchParams.get("limit"),"0");assert.equal(url.searchParams.get("after"),opaque);
  await client.getAdminUser("usr_a/b",{signal:controller.signal});
  assert.equal(calls[1].path,"/api/admin/users/usr_a%2Fb");
  for(const call of calls){
    assert(!Object.hasOwn(call.options.headers,"Authorization"));
    assert.equal(call.options.credentials,"same-origin");assert.equal(call.options.cache,"no-store");
    assert.equal(call.options.signal,controller.signal);
  }
  status=404;
  for(const read of [()=>client.getAdminUsers({after:opaque}),()=>client.getAdminUser("usr_missing")]){
    await assert.rejects(read(),error=>error.status===404&&!error.message.includes(opaque)&&!error.message.includes("after="));
  }
});

test("personal auth effects use same-origin cookies without mixing a legacy bearer and require real endpoints",async()=>{
  const calls=[],controller=new AbortController();let status=200;
  const client=createApiClient({tokenProvider:()=>"legacy-input",fetchImpl:async(path,options)=>{
    calls.push({path,options});return {ok:status===200,status,json:async()=>({user:{id:"fixture"}})};
  }});
  await client.getAuthStatus({signal:controller.signal});
  await client.loginAdmin({username:"fixture",password:"synthetic"},{signal:controller.signal});
  await client.getAdminSession({signal:controller.signal});
  await client.logoutAdmin({}, {csrfToken:"synthetic-csrf",signal:controller.signal});
  await client.completeAdminSetup({code:"synthetic",new_password:"synthetic"},{signal:controller.signal});
  assert.equal(calls.length,5);
  for(const call of calls){
    assert(!Object.hasOwn(call.options.headers,"Authorization"));
    assert.equal(call.options.credentials,"same-origin");assert.equal(call.options.cache,"no-store");
    assert.equal(call.options.signal,controller.signal);
  }
  assert.equal(calls[3].options.headers["X-Fleet-CSRF"],"synthetic-csrf");
  status=404;
  for(const read of [()=>client.getAuthStatus(),()=>client.getAdminSession()]){
    await assert.rejects(read(),error=>error.status===404);
  }
  status=200;await client.listAgents();
  assert.equal(calls.at(-1).options.headers.Authorization,"Bearer legacy-input");
});

test("catalog creation recognizes only scoped definitive rejection headers without reading error bodies",async()=>{
  let status=409,header="catalog_selection_changed",reads=0;
  const client=createApiClient({fetchImpl:async()=>({ok:false,status,headers:{get:key=>key==="Fleet-Catalog-Rejection"?header:null},json:async()=>{reads++;throw new Error("must not read");}})});
  for(header of ["catalog_selection_changed","catalog_target_unavailable","catalog_target_unsupported","catalog_target_capabilities_stale"]){
    await assert.rejects(client.createCatalogRunbookJob({}),error=>error.status===409&&error.catalogRejected===true);
  }
  for(header of ["job_already_exists","untrusted secret header"]){
    await assert.rejects(client.createCatalogRunbookJob({}),error=>error.catalogRejected===false&&!JSON.stringify(error).includes(header));
  }
  header="catalog_selection_changed";
  await assert.rejects(client.getJob("job-a"),error=>error.catalogRejected===false);
  status=500;
  await assert.rejects(client.createCatalogRunbookJob({}),error=>error.catalogRejected===false);
  assert.equal(reads,0);
});

test("catalog review and selector preview forward cancellation and preserve required read failures",async()=>{
  const controller=new AbortController(),calls=[];let status=200;
  const client=createApiClient({fetchImpl:async(path,options)=>{calls.push({path,options});return {ok:status===200,status,json:async()=>({})};}});
  await client.getCatalogDocumentDetail("source-a","a".repeat(40),"runbooks/a b.yaml",{signal:controller.signal});
  await client.previewSelector({selector:"role=web"},{signal:controller.signal});
  assert(calls.every(c=>c.options.signal===controller.signal));
  status=404;await assert.rejects(client.getCatalogDocumentDetail("source-a","a".repeat(40),"runbooks/a.yaml"),e=>e.status===404);
  controller.abort();const before=calls.length;
  await assert.rejects(client.previewSelector({selector:"role=web"},{signal:controller.signal}),e=>e===controller.signal.reason);assert.equal(calls.length,before);
});

test("catalog execution forwards one reference request and abort signal without automatic retry", async () => {
  const calls = [], controller = new AbortController(); let status = 201, parsed = 0;
  const client = createApiClient({ fetchImpl: async (path, options) => {
    calls.push({ path, options }); return { ok: status === 201, status, json: async () => { parsed++; return { job_id: "job-a" }; } };
  } });
  const body = { job_id: "job-a", source_id: "source-a", commit: "a".repeat(40), path: "runbooks/a.yml", checksum: "c".repeat(64) };
  assert.deepEqual(await client.createCatalogRunbookJob(body, { signal: controller.signal }), { job_id: "job-a" });
  assert.equal(calls[0].path, "/api/jobs/catalog-runbook");
  assert.equal(calls[0].options.method, "POST"); assert.equal(calls[0].options.signal, controller.signal);
  assert.deepEqual(JSON.parse(calls[0].options.body), body);
  for (status of [400, 401, 403, 404, 409, 500]) {
    const before = calls.length;
    await assert.rejects(client.createCatalogRunbookJob(body), error => error.status === status);
    assert.equal(calls.length, before + 1);
  }
  assert.equal(parsed, 1, "error bodies must not be read");
  controller.abort(); const before = calls.length;
  await assert.rejects(client.createCatalogRunbookJob(body, { signal: controller.signal }), error => error === controller.signal.reason);
  assert.equal(calls.length, before);
});

test("explicit Catalog mutations forward cancellation without changing their request bodies", async () => {
  const controller = new AbortController(), calls = [];
  const client = createApiClient({ tokenProvider: () => "test-token", fetchImpl: async (path, options) => { calls.push({ path, options }); return { ok: true, status: 202, json: async () => ({}) }; } });
  await client.registerCatalogSource({ source_id: "a" }, { signal: controller.signal });
  await client.startCatalogSync("a", { operation_id: "sync-a" }, { signal: controller.signal });
  await client.activateCatalogRevision("a", { commit: "a".repeat(40) }, { signal: controller.signal });
  assert(calls.every(call => call.options.signal === controller.signal && call.options.method === "POST"));
  assert.deepEqual(calls.map(call => JSON.parse(call.options.body)), [{ source_id: "a" }, { operation_id: "sync-a" }, { commit: "a".repeat(40) }]);
});
const response = (status, body = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

test("catalog sync status encodes both identities and forwards read cancellation", async () => {
  const calls = [], controller = new AbortController();
  const body = { id: "sync-a", source_id: "source-a", state: "in_progress", commit: null, failure: null };
  const client = createApiClient({ fetchImpl: async (path, options) => { calls.push({ path, options }); return response(200, body); } });
  assert.equal(await client.getCatalogSyncOperation("source/id", "sync+id", { signal: controller.signal }), body);
  assert.equal(calls[0].path, "/api/catalog/sources/source%2Fid/sync-operations/sync%2Bid");
  assert.equal(calls[0].options.signal, controller.signal);
});

test("catalog sync status treats missing/failing reads as errors without parsing private details", async () => {
  let status = 404, reads = 0;
  const client = createApiClient({ fetchImpl: async () => ({ ok: false, status, json: async () => { reads++; return { secret: "private" }; } }) });
  for (status of [400, 401, 403, 404, 500]) {
    await assert.rejects(client.getCatalogSyncOperation("source-a", "sync-a"), error => error.status === status && !error.message.includes("private"));
  }
  assert.equal(reads, 0);
});

test("catalog sync status abort before request does not contact the Controller", async () => {
  let calls = 0; const controller = new AbortController(); controller.abort();
  const client = createApiClient({ fetchImpl: async () => { calls++; return response(200); } });
  await assert.rejects(client.getCatalogSyncOperation("source-a", "sync-a", { signal: controller.signal }), error => error === controller.signal.reason);
  assert.equal(calls, 0);
});

for (const [name, read] of [
  ["sources", (client, options) => client.listCatalogSources(options)],
  ["revisions", (client, options) => client.listCatalogRevisions("source-a", options)],
  ["documents", (client, options) => client.listCatalogDocuments("source-a", "a".repeat(40), options)],
]) {
  test(`catalog ${name} keeps read ownership, required errors and opaque cursors out of diagnostics`, async () => {
    const controller = new AbortController(); let currentStatus = 200, reads = 0; const calls = [];
    const body = { items: [], next_after: null };
    const client = createApiClient({ fetchImpl: async (path, options) => {
      calls.push({ path, options });
      return { ok: currentStatus === 200, status: currentStatus, json: async () => { reads++; return body; } };
    } });
    assert.equal(await read(client, { after: "opaque+position", limit: 50, signal: controller.signal }), body);
    assert.equal(calls[0].options.signal, controller.signal); assert(calls[0].path.includes("after=opaque%2Bposition"));
    for (const status of [401, 403, 404, 500]) {
      currentStatus = status;
      await assert.rejects(read(client, { after: "private-cursor", signal: controller.signal }), error => {
        assert.equal(error.status, status); assert(!error.message.includes("private-cursor")); return true;
      });
    }
    assert.equal(reads, 1, "error response bodies must not be parsed");
    const before = calls.length; controller.abort();
    await assert.rejects(read(client, { signal: controller.signal }), error => error === controller.signal.reason);
    assert.equal(calls.length, before);
  });
}

test("output page forwards scoped cursor, exact abort signal and decimal strings", async () => {
  const calls = [];
  const controller = new AbortController();
  const body = { items: [{ chunk_key: "9007199254740993", sequence: "9007199254740994", data: "한🤖\0" }], next_after: "op1.next" };
  const client = createApiClient({ fetchImpl: async (path, options) => {
    calls.push({ path, options }); return response(200, body);
  } });
  assert.equal(await client.getJobOutputPage("job/+1", {
    after: "op1.a_b-1", agentId: "a+b", stream: "stderr", limit: 2, maxBytes: 4096, signal: controller.signal,
  }), body);
  assert.equal(calls[0].path, "/api/jobs/job%2F%2B1/output-page?after=op1.a_b-1&agent_id=a%2Bb&stream=stderr&limit=2&max_bytes=4096");
  assert.equal(calls[0].options.signal, controller.signal);
  assert.equal(body.items[0].chunk_key, "9007199254740993");
});

test("output page preserves invalid zero/empty values for server rejection and omits only absent options", async () => {
  const paths = [];
  const client = createApiClient({ fetchImpl: async (path) => { paths.push(path); return response(200, {}); } });
  await client.getJobOutputPage("job-1");
  await client.getJobOutputPage("job-1", { after: "", agentId: "", stream: "", limit: 0, maxBytes: 0 });
  assert.equal(paths[0], "/api/jobs/job-1/output-page");
  assert.equal(paths[1], "/api/jobs/job-1/output-page?after=&agent_id=&stream=&limit=0&max_bytes=0");
});

for (const status of [400, 401, 403, 404, 409, 413, 500]) {
  test(`output page HTTP ${status} rejects without reading a raw error body`, async () => {
    let reads = 0;
    const client = createApiClient({ fetchImpl: async () => ({ ok: false, status,
      json: async () => { reads += 1; return { output: "private" }; },
    }) });
    await assert.rejects(client.getJobOutputPage("job-1"), (error) => error.name === "ApiHttpError" && error.status === status && !error.message.includes("private"));
    assert.equal(reads, 0);
  });
}

test("output page abort rejects before starting a request", async () => {
  const controller = new AbortController(); controller.abort();
  let calls = 0;
  const client = createApiClient({ fetchImpl: async () => { calls += 1; return response(200, {}); } });
  await assert.rejects(client.getJobOutputPage("job-1", { signal: controller.signal }), (error) => error === controller.signal.reason);
  assert.equal(calls, 0);
});

test("output page errors keep opaque cursor and filter metadata out of diagnostics", async () => {
  let diagnosticPath;
  const client = createApiClient({
    formatError: (path) => { diagnosticPath = path; return `Read failed: ${path}`; },
    fetchImpl: async () => response(409),
  });
  await assert.rejects(client.getJobOutputPage("job-1", { after: "op1.private-state", agentId: "private-agent" }), (error) => {
    assert(!error.message.includes("private-state"));
    assert(!error.message.includes("private-agent"));
    return error.status === 409;
  });
  assert.equal(diagnosticPath, "/api/jobs/job-1/output-page");
});

for (const method of ["getJob", "getJobOutput"]) {
  test(`${method} forwards the exact abort signal and preserves the request`, async () => {
    const controller = new AbortController();
    const calls = [];
    const body = method === "getJob" ? { id: "job/1", status: "running" } : [];
    const client = createApiClient({
      tokenProvider: () => "fixture-token",
      fetchImpl: async (path, options) => {
        calls.push({ path, options });
        return response(200, body);
      },
    });

    assert.equal(await client[method]("job/1", { signal: controller.signal }), body);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, `/api/jobs/job%2F1${method === "getJobOutput" ? "/output" : ""}`);
    assert.equal(calls[0].options.signal, controller.signal);
    assert.equal(calls[0].options.headers.Authorization, "Bearer fixture-token");
    assert.equal(calls[0].options.body, undefined);
  });

  test(`${method} rejects a pre-aborted read without starting fetch`, async () => {
    const controller = new AbortController();
    controller.abort();
    let calls = 0;
    const client = createApiClient({ fetchImpl: async () => {
      calls += 1;
      return response(200);
    } });

    await assert.rejects(client[method]("job-1", { signal: controller.signal }),
      (error) => error === controller.signal.reason);
    assert.equal(calls, 0);
  });

  test(`${method} preserves an active cancellation reason without retry`, async () => {
    const controller = new AbortController();
    let observedSignal;
    let rejectFetch;
    let calls = 0;
    const client = createApiClient({ fetchImpl: (_path, options) => {
      calls += 1;
      observedSignal = options.signal;
      return new Promise((_resolve, reject) => {
        rejectFetch = reject;
        options.signal?.addEventListener("abort", () => reject(options.signal.reason), { once: true });
      });
    } });
    const pending = client[method]("job-1", { signal: controller.signal });
    const check = assert.rejects(pending, (error) => error === controller.signal.reason);
    controller.abort();
    // Settle the broken implementation too, so RED reports the contract mismatch, not a timeout.
    if (observedSignal !== controller.signal) rejectFetch(new Error("abort signal was not forwarded"));
    await check;
    assert.equal(observedSignal, controller.signal);
    assert.equal(calls, 1);
  });

  for (const status of [401, 403, 404, 500]) {
    test(`${method} exposes HTTP ${status} without reading the error body`, async () => {
      let bodyReads = 0;
      const client = createApiClient({ fetchImpl: async () => ({
        ok: false,
        status,
        json: async () => {
          bodyReads += 1;
          return { secret: "must-not-be-exposed" };
        },
      }) });

      await assert.rejects(client[method]("job-1"), (error) => {
        assert(error instanceof Error);
        assert.equal(error.name, "ApiHttpError");
        assert.equal(error.status, status);
        assert(!error.message.includes("must-not-be-exposed"));
        assert.equal("body" in error, false);
        return true;
      });
      assert.equal(bodyReads, 0);
    });
  }
}

test("a deferred successful Job read resolves the actual response without another fetch", async () => {
  let resolveFetch;
  let calls = 0;
  const client = createApiClient({ fetchImpl: () => {
    calls += 1;
    return new Promise((resolve) => { resolveFetch = resolve; });
  } });
  const pending = client.getJob("job-delayed");
  const body = { id: "job-delayed", status: "running" };
  resolveFetch(response(200, body));
  assert.equal(await pending, body);
  assert.equal(calls, 1);
});

test("artifact view reads forward cancellation without changing their default missing-data contract", async () => {
  const calls = [];
  const controller = new AbortController();
  const client = createApiClient({ fetchImpl: async (path, options) => {
    calls.push({ path, options });
    return response(404);
  } });
  assert.equal(await client.getJobArtifact("job/1", "artifact/1", { signal: controller.signal }), null);
  assert.equal(calls[0].path, "/api/jobs/job%2F1/artifacts/artifact%2F1");
  assert.equal(calls[0].options.signal, controller.signal);
  controller.abort();
  await assert.rejects(client.getJobArtifact("job/1", "artifact/1", { signal: controller.signal }));
  assert.equal(calls.length, 1);
});

test("optional missing data retains null and default reads do not invent request options", async () => {
  let options;
  const client = createApiClient({ fetchImpl: async (_path, requestOptions) => {
    options = requestOptions;
    return response(404);
  } });
  assert.equal(await client.getLatestDrift("agent-1"), null);
  assert.equal(await client.getLatestFacts("agent-1"), null);
  assert.equal("signal" in options, false);
  assert.equal("missingIsError" in options, false);
});

test("204 and network errors retain their existing meanings", async () => {
  const emptyClient = createApiClient({ fetchImpl: async () => response(204) });
  assert.equal(await emptyClient.getJob("job-empty"), null);
  const failure = new TypeError("network unavailable");
  const client = createApiClient({ fetchImpl: async () => { throw failure; } });
  await assert.rejects(client.getJobOutput("job-1"), (error) => error === failure);
});

test("custom safe messages are preserved alongside a classified status", async () => {
  const client = createApiClient({
    formatError: (path, status) => `${status}: ${path}`,
    fetchImpl: async () => response(403),
  });
  await assert.rejects(client.getJob("job-1"), (error) => {
    assert.equal(error.status, 403);
    assert.equal(error.message, "403: /api/jobs/job-1");
    return true;
  });
});


test("created catalog Job lists accept the caller-owned cancellation signal",async()=>{
  const controller=new AbortController(),calls=[];
  const client=createApiClient({fetchImpl:async(path,options)=>{calls.push({path,options});return {ok:true,status:200,json:async()=>[]};}});
  await client.listJobs({signal:controller.signal});await client.listApprovals("pending",{signal:controller.signal});
  assert(calls.every(c=>c.options.signal===controller.signal));
  controller.abort();const before=calls.length;
  await assert.rejects(client.listJobs({signal:controller.signal}),e=>e===controller.signal.reason);assert.equal(calls.length,before);
});

test("authentication generation aborts pending reads and rejects bodies settled after a user switch", async () => {
  let finish, signal;
  const pending = new Promise(resolve => { finish = resolve; });
  const client = createApiClient({ fetchImpl: async (_path, options) => {
    signal = options.signal; return { ok:true,status:200,json:()=>pending };
  }});
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-A"});
  const reading = client.listJobs().then(value=>({value}),error=>({error}));
  await Promise.resolve(); await Promise.resolve();
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-B"});
  finish([{id:"private-A"}]);
  const settled=await reading;
  assert.equal(signal?.aborted,true,"the prior request must be canceled on identity change");
  assert.equal(settled.error?.name,"AbortError","a late JSON body must not enter the new identity's view");
});

test("cookie business effects use current CSRF and a current 401 clears auth once without replay", async () => {
  const calls=[];let unauthorized=0;
  const client=createApiClient({tokenProvider:()=>"must-not-mix-bearer",
    onUnauthorized:()=>{unauthorized++;},fetchImpl:async(path,options)=>{
      calls.push({path,options});return {ok:false,status:401};
    }});
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-A"});
  await assert.rejects(client.createCommandJob({job_id:"one"}),error=>error.status===401);
  assert.equal(calls.length,1);assert.equal(unauthorized,1);
  assert.equal(calls[0].options.headers.Authorization,undefined);
  assert.equal(calls[0].options.headers["X-Fleet-CSRF"],"csrf-A");
  assert.equal(calls[0].options.credentials,"same-origin");
});

test("an old 401 cannot invalidate a new identity and an uncertain POST is never replayed",async()=>{
  let finish;let unauthorized=0;const calls=[];
  const pending=new Promise(resolve=>{finish=resolve;});
  const client=createApiClient({onUnauthorized:()=>{unauthorized++;},fetchImpl:async(path,options)=>{
    calls.push({path,options});return pending;
  }});
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-A"});
  const creating=client.createCatalogRunbookJob({job_id:"uncertain-A"}).catch(error=>error);
  await Promise.resolve();
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-B"});
  finish({ok:false,status:401});
  assert.equal((await creating).name,"AbortError");
  assert.equal(unauthorized,0);assert.equal(calls.length,1,"no POST or replacement Job is automatic");
});

test("successful logout retires pending reads and forbidden responses keep the current identity",async()=>{
  let finish;let notified=0;const calls=[];
  const pending=new Promise(resolve=>{finish=resolve;});
  const client=createApiClient({onUnauthorized:()=>{notified++;},fetchImpl:async(path,options)=>{
    calls.push({path,options});
    if(path==="/api/jobs") return pending;
    if(path==="/api/auth/logout") return {ok:true,status:204};
    return {ok:false,status:403};
  }});
  client.setAuthentication?.({mode:"cookie",csrfToken:"csrf-A"});
  await assert.rejects(client.createCommandJob({job_id:"forbidden"}),error=>error.status===403);
  const request=client.listJobs().catch(error=>error);
  await client.logoutAdmin({},{csrfToken:"csrf-A"});
  finish({ok:true,status:200,json:async()=>[{id:"private-A"}]});
  assert.equal((await request).name,"AbortError");
  assert.equal(notified,0,"403 is a permission failure, not a forced logout");
  assert.equal(calls[1].options.signal.aborted,true);
});
