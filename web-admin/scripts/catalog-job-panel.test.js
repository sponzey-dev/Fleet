import test from "node:test";
import assert from "node:assert/strict";
import * as app from "../app.js";
const commit="a".repeat(40), checksum="c".repeat(64);
const settle=async()=>{for(let i=0;i<70;i++)await Promise.resolve();};
class Element extends EventTarget {
  value="";checked=false;textContent="";innerHTML="";disabled=false;hidden=false;attributes={};focusCalls=0;
  setAttribute(k,v){this.attributes[k]=v;}
  focus(){this.focusCalls++;if(this.ownerDocument)this.ownerDocument.activeElement=this;}
  click(){if(!this.disabled)this.dispatchEvent(new Event("click"));}
  input(value){this.value=value;this.dispatchEvent(new Event("input"));}
  confirm(){this.checked=true;this.dispatchEvent(new Event("change"));}
}
function harness(overrides={}){
  assert.equal(typeof app.createCatalogJobPanel,"function","real Catalog Job panel must compose the owner");
  const elements=Object.fromEntries(["panel","reference","selector","preview","body","confirm","review","submit","check","retry","reset","status"].map(k=>[k,new Element()]));
  const document={activeElement:null};for(const e of Object.values(elements))e.ownerDocument=document;
  const calls=[],created=[],timers=new Map();let timer=0;
  const panel=app.createCatalogJobPanel({elements,makeJobId:()=>"job-a",clock:{setTimeout(fn){timers.set(++timer,fn);return timer;},clearTimeout:id=>timers.delete(id)},onCreated:job=>created.push(job),apiClient:{
    getCatalogDocumentDetail:()=>({kind:"runbook",path:"runbooks/safe.yaml",checksum,body:"<script>public document</script>"}),
    previewSelector:()=>({matched_count:1,selected_count:1,disabled_count:0,offline_count:1,warnings:[],agents:[{agent_id:"agent-a",name:"<img src=x>",status:"offline",labels:[],selected_for_dispatch:true}]}),
    createCatalogRunbookJob:(body,options)=>{calls.push([body,options]);return overrides.create?.(body,options)??{job_id:"job-a",target_count:1,assignment_count:1,status:"pending_approval",approval_request_id:"approval-a"};},
    getJob:()=>({id:"job-a",status:"pending_approval",target_agent_ids:["agent-a"],catalog_provenance:{source_id:"source-a",commit,path:"runbooks/safe.yaml",checksum}}),
  }});
  panel.setContext({route:"runbooks",authenticated:true});
  const select=(extra={})=>panel.setSelection({selectedSource:{id:"source-a",active_commit:commit},selectedRevision:{commit,state:"ready"},selectedDocument:{kind:"runbook",path:"runbooks/safe.yaml",checksum},selectionStale:false,...extra});
  select();return{panel,elements,calls,created,timers,select};
}
test("real catalog Job panel shows immutable review, escaped preview and submits once into the shared result callback",async()=>{
  const h=harness();assert(h.elements.submit.disabled);h.elements.selector.input("role=web");h.elements.review.click();await settle();
  assert.equal(h.elements.body.textContent,"<script>public document</script>");assert(h.elements.reference.textContent.includes(commit));assert(h.elements.reference.textContent.includes(checksum));
  assert(h.elements.preview.innerHTML.includes("&lt;img"));assert(!h.elements.preview.innerHTML.includes("<img"));assert(h.elements.submit.disabled);
  h.elements.confirm.confirm();h.elements.submit.click();h.elements.submit.click();await settle();
  assert.equal(h.calls.length,1);assert.deepEqual(h.calls[0][0].target_agent_ids,["agent-a"]);assert(!("runbook_document"in h.calls[0][0]));
  assert.equal(h.created[0].job_id,"job-a");assert.match(h.elements.status.textContent,/approval/);assert(h.elements.submit.disabled);h.panel.dispose();assert.equal(h.timers.size,0);
});
test("real catalog Job panel invalidates reviewed targets on edits, stale selection and route retirement",async()=>{
  const h=harness();h.elements.selector.input("role=web");h.elements.review.click();await settle();h.elements.confirm.confirm();
  h.elements.selector.input("role=db");assert(h.elements.submit.disabled);assert.equal(h.elements.body.textContent,"");assert.equal(h.elements.confirm.checked,false);
  h.select({selectionStale:true});assert(h.elements.review.disabled);
  h.panel.setContext({route:"policies",authenticated:true});assert(h.elements.panel.hidden);h.elements.submit.click();assert.equal(h.calls.length,0);h.panel.dispose();
});
test("real catalog Job panel removes effects on disposal",async()=>{
  const h=harness();h.panel.dispose();h.elements.selector.input("role=web");h.elements.review.click();h.elements.confirm.confirm();h.elements.submit.click();await settle();assert.equal(h.calls.length,0);assert.equal(h.timers.size,0);
});

test("shared results distinguish immutable catalog provenance, raw Jobs and an unavailable or invalid field",()=>{
  assert.equal(typeof app.formatJobCatalogProvenance,"function");
  const source={source_id:"source-a",commit,path:"runbooks/safe.yaml",checksum};
  const formatted=app.formatJobCatalogProvenance({catalog_provenance:source});assert(formatted.includes(commit));assert(formatted.includes(checksum));assert(formatted.includes(source.path));
  assert.match(app.formatJobCatalogProvenance({catalog_provenance:null}),/No catalog provenance/);
  assert.match(app.formatJobCatalogProvenance({}),/not reported/);
  assert.match(app.formatJobCatalogProvenance({catalog_provenance:{...source,checksum:"wrong"}}),/could not be verified/);
});

test("review and submit controls preserve keyboard focus while busy and hand confirmed completion to status",async()=>{
  let resolve;const pending=new Promise(r=>{resolve=r;});const h=harness({create:()=>pending});
  h.elements.selector.input("role=web");h.elements.review.focus();h.elements.review.click();await settle();
  assert.equal(h.elements.review.ownerDocument.activeElement,h.elements.review);
  h.elements.confirm.confirm();h.elements.submit.focus();h.elements.submit.click();await settle();
  assert.equal(h.elements.submit.disabled,false,"busy focused control remains focusable");
  assert.equal(h.elements.submit.attributes["aria-disabled"],"true");
  h.elements.submit.click();assert.equal(h.calls.length,1);
  resolve({job_id:"job-a",target_count:1,assignment_count:1,status:"pending_approval",approval_request_id:"approval-a"});await settle();
  assert.equal(h.elements.status.ownerDocument.activeElement,h.elements.status);h.panel.dispose();
});
