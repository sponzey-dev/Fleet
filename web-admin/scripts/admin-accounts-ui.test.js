/** @file Real HTML/event/FormData integration with simulated HTTP; never controls a browser or creates live credentials. */
import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {JSDOM,VirtualConsole} from "jsdom";
const html=readFileSync(new URL("../index.html",import.meta.url),"utf8");
const css=readFileSync(new URL("../styles.css",import.meta.url),"utf8");
const settle=async()=>{for(let n=0;n<100;n++)await Promise.resolve();};
let fixtureId=0;
async function fixture({role="owner",restored=false,loginStatus=200,displayName="Fixture owner"}={}) {
  const errors=[],console=new VirtualConsole();console.on("jsdomError",error=>errors.push(error.type));
  const dom=new JSDOM(html,{url:"https://fleet.test/admin/#settings",pretendToBeVisual:true,virtualConsole:console});
  const {window}=dom,document=window.document;
  const style=document.createElement("style");style.textContent=css;document.head.append(style);
  const calls=[],timers=new Map();let nextTimer=0,tokenCreated=false;
  const user={id:"usr_fixture_A",username:"fixture_owner",display_name:displayName,role,status:"active"};
  const users=[user];
  const session={user,expires_at:Math.floor(Date.now()/1000)+28800,csrf_token:"fixture-private-csrf"};
  const response=(status,body)=>({ok:status>=200&&status<300,status,headers:new Headers(),json:async()=>structuredClone(body)});
  const fetch=async(path,options={})=>{
    calls.push({path,options});const url=new URL(path,"https://fleet.test"),method=options.method||"GET";
    if(url.pathname==="/api/auth/status")return response(200,{mode:"personal"});
    if(url.pathname==="/api/auth/session")return response(restored?200:401,restored?session:{});
    if(url.pathname==="/api/auth/login")return response(loginStatus,loginStatus===200?session:{});
    if(url.pathname==="/api/auth/logout")return response(204,null);
    if(url.pathname==="/api/auth/tokens"&&method==="POST"){tokenCreated=true;return response(201,{token:{id:"crd_fixture",secret:"fixture-once-secret",expires_at:session.expires_at+2592000}});}
    if(url.pathname==="/api/auth/tokens")return response(200,{items:tokenCreated?[{id:"crd_fixture",label:null,created_at:1,expires_at:2592000,active:true}]:[],next_cursor:null});
    if(url.pathname==="/api/auth/password")return response(204,null);
    if(url.pathname==="/api/admin/users"&&method==="POST"){
      const body=JSON.parse(options.body);assert.deepEqual(Object.keys(body).sort(),["current_password","display_name","role","username"]);
      const created={id:"usr_fixture_B",username:body.username,display_name:body.display_name,role:body.role,status:"pending_setup"};users.push(created);
      return response(201,{user:created,setup:{code:"fixture-once-setup",expires_at:session.expires_at}});
    }
    if(url.pathname==="/api/admin/users")return response(200,{items:users,next_cursor:null});
    if(url.pathname==="/api/admin/users/usr_fixture_B"&&method==="PATCH"){
      const body=JSON.parse(options.body);assert.equal(body.current_password,"fixture-private-password");
      const target=users.find(value=>value.id==="usr_fixture_B");
      if(body.disable)target.status="disabled";else{target.display_name=body.display_name;target.role=body.role;}
      return response(200,{user:target});
    }
    if(url.pathname==="/api/admin/users/usr_fixture_B/password-reset")return response(201,{reset:{code:"fixture-once-reset",expires_at:session.expires_at}});
    if(url.pathname==="/api/catalog/sources")return response(200,{items:[],next_after:null});
    if(url.pathname==="/api/audit/export")return response(200,{items:[],next_before:null});
    if(url.pathname==="/api/controller/signing-rotation/status")return response(200,{});
    if(["/api/agents","/api/jobs","/api/approvals","/api/policies","/api/remediations","/api/enrollment-tokens"].includes(url.pathname))return response(200,[]);
    throw new Error("Unexpected simulated route.");
  };
  const replacements={document,location:window.location,FormData:window.FormData,fetch,
    addEventListener:window.addEventListener.bind(window),
    setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer;},clearTimeout:id=>timers.delete(id),
    confirm:()=>true,navigator:{clipboard:{writeText:async()=>{}}}};
  const original=Object.fromEntries(Object.keys(replacements).map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)]));
  for(const [key,value]of Object.entries(replacements))Object.defineProperty(globalThis,key,{value,writable:true,configurable:true});
  const close=async()=>{
    window.dispatchEvent(new window.Event("pagehide"));await settle();window.close();
    for(const [key,descriptor]of Object.entries(original)){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}
    assert.equal(timers.size,0,"all account deadlines and session expiry must be released");
  };
  try{await import("../app.js?account-fixture="+(++fixtureId));await settle();}
  catch(error){await close();throw error;}
  return {window,document,calls,errors,close,
    async login(){
      document.querySelector("#login-username").value="fixture_owner";
      document.querySelector("#login-password").value="fixture-private-password";
      document.querySelector("#personal-login-form").dispatchEvent(new window.SubmitEvent("submit",{cancelable:true,submitter:document.querySelector("#personal-login-form button")}));
      assert.equal(document.querySelector("#login-password").value,"","password is cleared before the network effect settles");
      await settle();
    }};
}

test("the real login DOM binds labels, clears proof and hides legacy authentication after personal login",async()=>{
  const h=await fixture();
  try{
    assert.equal(h.document.querySelector("#login-username").labels[0].textContent,"Username");
    assert.equal(h.document.querySelector("#login-password").type,"password");
    await h.login();
    assert.equal(h.document.querySelector("#personal-login").hidden,true);
    assert.equal(h.window.getComputedStyle(h.document.querySelector("#admin-auth")).display,"none","hidden legacy token form must not override the personal header");
    assert(h.document.querySelector("#current-admin-user").textContent.includes("Fixture owner"));
    assert(h.calls.some(c=>c.path.startsWith("/api/admin/users")));
    assert.equal(h.window.localStorage.length,0);assert.equal(h.window.sessionStorage.length,0);
    assert(!h.document.documentElement.outerHTML.includes("fixture-private-password"));
    assert(!h.document.documentElement.outerHTML.includes("fixture-private-csrf"));
  }finally{await h.close();}
});
test("a restored personal session loads actual account metadata at Settings without renewing or reposting login",async()=>{
  const h=await fixture({restored:true});
  try{
    assert(h.document.querySelector("#current-admin-user").textContent.includes("Fixture owner"));
    assert(h.calls.some(c=>c.path.startsWith("/api/admin/users")),"restored owner must load the existing accounts");
    assert(h.calls.some(c=>c.path.startsWith("/api/auth/tokens")),"restored person must load own token metadata");
    assert.equal(h.calls.filter(c=>c.path==="/api/auth/login").length,0);
    assert(h.document.querySelector("#admin-users-list").textContent.includes("Fixture owner"));
  }finally{await h.close();}
});
test("one-time token display uses only a property, does not reappear on metadata reads and clears on dismissal",async()=>{
  const h=await fixture();
  try{
    await h.login();
    const form=h.document.querySelector("#personal-token-form"),button=form.querySelector("button");
    button.getClientRects=()=>[{width:10,height:10}];
    h.document.querySelector("#personal-token-label").value="Laptop";
    h.document.querySelector("#personal-token-password").value="fixture-private-password";
    form.dispatchEvent(new h.window.SubmitEvent("submit",{cancelable:true,submitter:button}));
    assert.equal(h.document.querySelector("#personal-token-password").value,"");
    await settle();
    const once=h.document.querySelector("#once-secret");
    assert.equal(once.value,"fixture-once-secret");assert.equal(once.type,"password");
    assert.equal(once.hasAttribute("value"),false);
    assert(!h.document.documentElement.outerHTML.includes("fixture-once-secret"));
    assert(!h.document.documentElement.outerHTML.includes("fixture-private-password"));
    assert.equal(h.calls.filter(c=>c.path==="/api/auth/tokens"&&c.options.method==="POST").length,1);
    h.document.querySelector("#dismiss-once-secret").click();await settle();
    assert.equal(once.value,"");assert.equal(h.document.querySelector("#once-secret-panel").hidden,true);
    assert.equal(h.document.activeElement,button,"closing returns keyboard focus to the originating action");
    h.document.querySelector("#refresh-personal-tokens").click();await settle();
    assert.equal(once.value,"");assert.equal(h.document.querySelector("#once-secret-panel").hidden,true);
    assert(h.document.querySelector("#personal-tokens-list").textContent.includes("Unlabeled token"));
  }finally{await h.close();}
});
test("viewer UI retains self credentials while owner controls and enrollment queries remain unavailable",async()=>{
  const h=await fixture({role:"viewer"});
  try{
    await h.login();
    assert.equal(h.document.querySelector("#personal-account-panel").hidden,false);
    assert.equal(h.document.querySelector("#owner-accounts-panel").hidden,true);
    assert.equal(h.calls.filter(c=>c.path.startsWith("/api/admin/users")||c.path.startsWith("/api/enrollment-tokens")).length,0);
    h.document.querySelector("#settings-controller-tab").click();await settle();
    assert.equal(h.document.querySelector(".token-panel").hidden,true,"do not show a false empty enrollment list to a forbidden role");
    assert([...h.document.querySelectorAll("#staged-trust-bundle-form input, #staged-trust-bundle-form button, #staged-trust-bundle-form textarea")].every(control=>control.disabled));
  }finally{await h.close();}
});

test("owner create/edit/reset/disable binds current-password proofs and preserves immutable selected IDs",async()=>{
  const h=await fixture();
  try{
    await h.login();
    h.document.querySelector("#settings-people-tab").click();await settle();
    h.document.querySelector("#new-admin-username").value="second_person";
    h.document.querySelector("#new-admin-name").value="Second <person>";
    h.document.querySelector("#new-admin-role").value="operator";
    h.document.querySelector("#create-admin-password").value="fixture-private-password";
    h.document.querySelector("#create-admin-user-form").dispatchEvent(new h.window.SubmitEvent("submit",{cancelable:true}));
    assert.equal(h.document.querySelector("#create-admin-password").value,"");
    await settle();
    assert.equal(h.document.querySelector("#once-secret").value,"fixture-once-setup");
    h.document.querySelector("#dismiss-once-secret").click();
    const row=h.document.querySelector('[data-user-id="usr_fixture_B"]');assert(row);
    assert(row.innerHTML.includes("&lt;person&gt;"));row.click();
    assert.equal(h.document.activeElement,h.document.querySelector("#edit-admin-name"));
    h.document.querySelector("#edit-admin-role").value="viewer";
    h.document.querySelector("#edit-admin-password").value="fixture-private-password";
    h.document.querySelector("#edit-admin-user-form").dispatchEvent(new h.window.SubmitEvent("submit",{cancelable:true}));
    await settle();
    const patch=h.calls.find(c=>c.path==="/api/admin/users/usr_fixture_B"&&c.options.method==="PATCH");
    assert.equal(JSON.parse(patch.options.body).role,"viewer");
    assert.equal(patch.options.headers["X-Fleet-CSRF"],"fixture-private-csrf");
    h.document.querySelector("#edit-admin-password").value="fixture-private-password";
    h.document.querySelector("#reset-admin-password").click();await settle();
    assert.equal(h.document.querySelector("#once-secret").value,"fixture-once-reset","reset-only wire response must display the new code once");
    h.document.querySelector("#dismiss-once-secret").click();
    h.document.querySelector("#edit-admin-password").value="fixture-private-password";
    h.document.querySelector("#disable-admin-user").click();await settle();
    const disabled=h.calls.find(c=>c.options.method==="PATCH"&&JSON.parse(c.options.body).disable);
    assert.equal(disabled.path,"/api/admin/users/usr_fixture_B");
    assert(h.document.querySelector("#admin-users-list").textContent.includes("disabled"));
    assert(!h.document.documentElement.outerHTML.includes("fixture-private-password"));
  }finally{await h.close();}
});
test("an authentication error is announced and associated with the submitted fields without retaining proof",async()=>{
  const h=await fixture({loginStatus:401});
  try{
    await h.login();
    assert.equal(h.document.querySelector("#account-error").hidden,false);
    assert.equal(h.document.querySelector("#account-error").getAttribute("role"),"alert");
    assert.equal(h.document.querySelector("#personal-login-form").getAttribute("aria-describedby"),"account-error");
    assert.equal(h.document.querySelector("#login-password").getAttribute("aria-invalid"),"true");
    assert.equal(h.document.querySelector("#login-password").value,"");
    assert(!h.document.documentElement.outerHTML.includes("fixture-private-password"));
  }finally{await h.close();}
});

test("Settings divides personal, people and Controller flows with keyboard-operable tabs",async()=>{
  const h=await fixture();
  try{
    await h.login();
    const account=h.document.querySelector("#settings-account-tab");
    const people=h.document.querySelector("#settings-people-tab");
    const controller=h.document.querySelector("#settings-controller-tab");
    assert(account&&people&&controller,"separate related Settings flows rather than stacking every form");
    assert.equal(account.getAttribute("aria-selected"),"true");
    assert.equal(h.document.querySelector("#personal-account-panel").hidden,false);
    assert.equal(h.document.querySelector("#owner-accounts-panel").hidden,true);
    account.focus();account.dispatchEvent(new h.window.KeyboardEvent("keydown",{key:"ArrowRight",bubbles:true,cancelable:true}));
    assert.equal(h.document.activeElement,people);
    assert.equal(people.getAttribute("aria-selected"),"true");
    assert.equal(h.document.querySelector("#owner-accounts-panel").hidden,false);
    assert.equal(h.document.querySelector("#controller-settings-panel").hidden,true);
    people.dispatchEvent(new h.window.KeyboardEvent("keydown",{key:"End",bubbles:true,cancelable:true}));
    assert.equal(h.document.activeElement,controller);
    assert.equal(h.document.querySelector("#controller-settings-panel").hidden,false);
  }finally{await h.close();}
});

test("non-owner roles keep server-derived Controller and Job capabilities distinct",async()=>{
  for(const role of ["admin","operator","viewer"]){
    const h=await fixture({role});
    try{
      await h.login();
      assert.equal(h.document.querySelector("#settings-people-tab").hidden,true);
      h.document.querySelector("#settings-controller-tab").click();await settle();
      assert.equal(h.document.querySelector(".token-panel").hidden,role!=="admin");
      const staged=h.document.querySelector("#staged-trust-bundle-form button");
      assert.equal(staged.disabled,role!=="admin");
      h.window.location.hash="#run";
      h.window.dispatchEvent(new h.window.HashChangeEvent("hashchange"));await settle();
      assert.equal(h.document.querySelector("#run-command-form button[type=submit]").disabled,role==="viewer");
      assert.equal(h.document.querySelector("#job-permission-note").hidden,role!=="viewer");
    }finally{await h.close();}
  }
});

test("empty display text falls back to username and a maximum Unicode display name remains plain text",async()=>{
  for(const displayName of ["","💼".repeat(120)]){
    const h=await fixture({restored:true,displayName});
    try{
      const header=h.document.querySelector("#current-admin-user");
      assert.equal(header.textContent,(displayName||"fixture_owner")+" · owner");
      assert.equal(header.children.length,0);
      assert.equal(header.getAttribute("href"),"#settings");
      assert(h.document.querySelector("#new-admin-name").maxLength>=displayName.length,"a valid 120-code-point name must fit the HTML UTF-16 input limit");
      assert(h.document.querySelector("#edit-admin-name").maxLength>=displayName.length);
    }finally{await h.close();}
  }
});
