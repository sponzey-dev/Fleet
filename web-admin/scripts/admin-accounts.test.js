/** @file Memory-only account effects; fake credentials and owned clock, no network or storage. */
import test from "node:test";
import assert from "node:assert/strict";
import { createAdminAccounts } from "../admin-accounts.js";
const person=(role="owner",id="usr_A")=>({id,username:id,display_name:"Fixture person",role,status:"active",record_revision:1});
const session=(role="owner",id="usr_A")=>({user:person(role,id),expires_at:28800,csrf_token:"private-csrf"});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const settle=async()=>{for(let n=0;n<20;n++)await Promise.resolve();};
function harness(overrides={}) {
  const calls=[],views=[],once=[],clears=[],timers=new Map();let timer=0,generation=0;
  const api={
    setAuthentication(value){calls.push(["authentication",value]);return ++generation;},
    getAuthGeneration:()=>generation,
    getAuthStatus:async()=>({mode:"personal"}),
    getAdminSession:async()=>{throw {status:401};},
    loginAdmin:async()=>session(),logoutAdmin:async()=>null,completeAdminSetup:async()=>null,
    getAdminUsers:async()=>({items:[person()],next_cursor:null}),getAdminPersonalTokens:async()=>({items:[],next_cursor:null}),
    createAdminUser:async()=>({user:person("operator","usr_B"),setup:{code:"private-setup",expires_at:900}}),
    changeAdminUser:async()=>({user:person("viewer")}),resetAdminUserPassword:async()=>({reset:{code:"private-reset",expires_at:900}}),
    changeOwnAdminPassword:async()=>null,createAdminPersonalToken:async()=>({token:{id:"crd_A",secret:"private-token",expires_at:2592000}}),
    revokeAdminPersonalToken:async()=>null,
    ...overrides,
  };
  for(const name of Object.keys(api).filter(name=>!["setAuthentication","getAuthGeneration"].includes(name))) {
    const effect=api[name];api[name]=(...args)=>{calls.push([name,...args]);return effect(...args);};
  }
  const owner=createAdminAccounts({api,onChange:view=>views.push(view),onOnce:value=>once.push(value),onInvalidate:()=>clears.push(true),
    now:()=>0,clock:{setTimeout:(fn,ms)=>{timers.set(++timer,{fn,ms});return timer;},clearTimeout:id=>timers.delete(id)}});
  return {owner,calls,views,once,clears,timers};
}
test("mandatory auth404 is an error while personal401 requires sign-in without fallback or retry",async()=>{
  const broken=harness({getAuthStatus:async()=>{throw {status:404};}});
  await broken.owner.start();assert.equal(broken.owner.getSnapshot().phase,"error");
  assert.equal(broken.calls.filter(c=>c[0]==="getAuthStatus").length,1);
  assert.equal(broken.calls.filter(c=>c[0]==="getAdminSession").length,0);broken.owner.dispose();
  const h=harness();await h.owner.start();
  assert.equal(h.owner.getSnapshot().phase,"signed_out");assert.equal(h.owner.getSnapshot().mode,"personal");
  assert.equal(h.calls.filter(c=>c[0]==="getAdminSession").length,1);h.owner.dispose();
});
test("login and self token issuance never publish password, CSRF or once-only material in snapshots",async()=>{
  const h=harness();await h.owner.start();await h.owner.login("fixture","private-password");
  assert.equal(h.owner.getSnapshot().user.role,"owner");
  await h.owner.createToken({label:"Laptop",current_password:"private-password"});
  assert.equal(h.once.length,1);assert.equal(h.once[0].value,"private-token");
  assert(!JSON.stringify(h.views).includes("private-"));
  assert.equal(h.calls.filter(c=>c[0]==="createAdminPersonalToken").length,1);
  await h.owner.loadTokens();assert.equal(h.once.length,1,"metadata reads cannot redisplay the secret");
  await h.owner.logout();assert.equal(h.owner.getSnapshot().user,null);
  assert.equal(h.timers.size,0);h.owner.dispose();
});
test("late login A cannot replace B and owner management is unavailable for all other roles",async()=>{
  const old=deferred();let n=0;
  const h=harness({loginAdmin:()=>++n===1?old.promise:session("operator","usr_B")});
  const a=h.owner.login("A","private-A");await settle();
  const b=h.owner.login("B","private-B");await b;
  old.resolve(session());await a;
  assert.equal(h.owner.getSnapshot().user.id,"usr_B");
  await h.owner.createUser({username:"other",current_password:"private-B"});
  assert.equal(h.calls.filter(c=>c[0]==="createAdminUser").length,0);
  assert.equal(h.owner.getSnapshot().error.kind,"forbidden");h.owner.dispose();
});
test("owner creation delivers setup once and own role change retires the whole local context",async()=>{
  const h=harness();await h.owner.login("owner","private-password");
  await h.owner.createUser({username:"other",current_password:"private-password"});
  assert.equal(h.once[0].value,"private-setup");
  assert(!JSON.stringify(h.owner.getSnapshot()).includes("private-"));
  await h.owner.changeUser("usr_A",{role:"viewer",current_password:"private-password"});
  assert.equal(h.owner.getSnapshot().user,null);assert.equal(h.owner.getSnapshot().phase,"signed_out");
  assert.equal(h.timers.size,0);h.owner.dispose();
});
test("every active role may replace its own password and fixed session expiry never renews on metadata reads",async()=>{
  for(const role of ["owner","admin","operator","viewer"]){
    const h=harness({loginAdmin:async()=>session(role)});
    await h.owner.login("fixture","private-password");
    const expiry=[...h.timers.values()].find(t=>t.ms===28800000);
    await h.owner.loadTokens();assert([...h.timers.values()].includes(expiry),"polling must not renew expiry");
    await h.owner.changePassword({current_password:"private-password",new_password:"private-next"});
    assert.equal(h.calls.filter(c=>c[0]==="changeOwnAdminPassword").length,1);
    assert.equal(h.owner.getSnapshot().user,null);assert.equal(h.timers.size,0);h.owner.dispose();
  }
});

test("logout during an account effect still revokes the web session and suppresses late secret delivery",async()=>{
  const pending=deferred();const h=harness({createAdminPersonalToken:()=>pending.promise});
  try{
    await h.owner.login("fixture","private-password");
    const issuing=h.owner.createToken({current_password:"private-password"});
    await settle();
    assert.equal(h.calls.filter(c=>c[0]==="createAdminPersonalToken").length,1);
    await h.owner.logout();
    assert.equal(h.calls.filter(c=>c[0]==="logoutAdmin").length,1,"logout must reach the server even while another account request was pending");
    pending.resolve({token:{id:"crd_late",secret:"private-late-token",expires_at:2592000}});
    await issuing;await settle();
    assert.equal(h.once.length,0);
    assert.equal(h.owner.getSnapshot().user,null);
    assert.equal(h.timers.size,0);
  }finally{h.owner.dispose();}
});
