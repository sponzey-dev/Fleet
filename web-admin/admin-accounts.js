/** @file Memory-only human account effects, separate from operational Job state and DOM. */

const ROLES = new Set(["owner", "admin", "operator", "viewer"]);
function userView(value) {
  if (!value || typeof value.id !== "string" || !value.id || value.id.length > 256
      || typeof value.username !== "string" || !value.username || value.username.length > 256
      || typeof value.display_name !== "string" || value.display_name.length > 256
      || !ROLES.has(value.role) || !["active", "pending_setup", "disabled"].includes(value.status)) throw new Error("Invalid account response.");
  return Object.freeze({id:value.id,username:value.username,display_name:value.display_name,role:value.role,status:value.status});
}
function sessionView(value) {
  const user=userView(value?.user);
  if(user.status!=="active" || !Number.isSafeInteger(value.expires_at) || value.expires_at<=0
      || typeof value.csrf_token!=="string" || !value.csrf_token || value.csrf_token.length>1024) throw new Error("Invalid login response.");
  return {user,expiresAt:value.expires_at,csrfToken:value.csrf_token};
}
function safeFailure(error) {
  const status=Number(error?.status)||0;
  const kind=status===401?"authentication":status===403?"forbidden":status===404?"missing"
    :status===409?"conflict":status===429?"busy":status===400?"invalid":"unavailable";
  const message={
    authentication:"Login failed or expired. Check your details and sign in again.",
    forbidden:"Your account does not have permission for this action.",
    missing:"A required account API or record was not found. Refresh and check the Controller version.",
    conflict:"The account changed, the username exists, or last-owner protection applies. Refresh accounts before trying again.",
    busy:"Authentication is busy. Wait a moment and try again.",
    invalid:"Check the fields. Use a valid username and a long, uncommon password of at least 15 characters.",
    unavailable:"The request could not be confirmed. Refresh the relevant record before trying again.",
  }[kind];
  return Object.freeze({kind,status,message});
}

/**
 * Owns one bounded account effect and the fixed web-session deadline.
 * Passwords, CSRF and once-only credentials are excluded from snapshots.
 * onOnce receives a delivery value once; its consumer owns clearing its display.
 */
export function createAdminAccounts({api,onChange=()=>{},onOnce=()=>{},onInvalidate=()=>{},clock=globalThis,now=()=>Date.now()}) {
  let owner={},pending=null,expiry=null,disposed=false,csrfToken="";
  let state={mode:"checking",phase:"loading",user:null,expiresAt:null,busy:false,error:null,
    message:"Checking login availability.",users:[],userCursor:null,tokens:[],tokenCursor:null};
  const snapshot=()=>Object.freeze({...state,users:Object.freeze([...state.users]),tokens:Object.freeze([...state.tokens])});
  const current=token=>!disposed&&owner===token;
  function publish() {
    if(disposed)return false;
    try{onChange(snapshot());return !disposed;}catch{disposed=true;pending?.abort();if(expiry!==null)clock.clearTimeout(expiry);return false;}
  }
  function retire(message="",mode=state.mode) {
    owner={};pending?.abort(new DOMException("Account context changed.","AbortError"));pending=null;
    if(expiry!==null)clock.clearTimeout(expiry);expiry=null;csrfToken="";
    api.setAuthentication({mode:"anonymous"});
    state={mode,phase:"signed_out",user:null,expiresAt:null,busy:false,error:null,message,users:[],userCursor:null,tokens:[],tokenCursor:null};
    onInvalidate();
  }
  function activate(value) {
    const parsed=sessionView(value);
    csrfToken=parsed.csrfToken;
    state={...state,mode:"personal",phase:"authenticated",user:parsed.user,expiresAt:parsed.expiresAt,error:null,message:"Signed in."};
    api.setAuthentication({mode:"cookie",csrfToken});
    if(expiry!==null)clock.clearTimeout(expiry);
    expiry=clock.setTimeout(()=>{retire("Your login expired. Sign in again.","personal");publish();},
      Math.max(0,Math.min(28800000,parsed.expiresAt*1000-now())));
  }
  async function run(effect,{user=false,ownerOnly=false}={}) {
    if(disposed||state.busy)return null;
    if((user&&!state.user)||(ownerOnly&&state.user?.role!=="owner")){
      state={...state,error:safeFailure({status:state.user?403:401})};publish();return null;
    }
    const token=owner,controller=new AbortController();pending=controller;
    state={...state,busy:true,error:null};if(!publish()||!current(token))return null;
    const deadline=clock.setTimeout(()=>controller.abort(new DOMException("Account request timed out.","TimeoutError")),10000);
    let abort;
    const canceled=new Promise((_,reject)=>{abort=()=>reject(controller.signal.reason);controller.signal.addEventListener("abort",abort,{once:true});});
    try{
      const result=await Promise.race([Promise.resolve().then(()=>{controller.signal.throwIfAborted();return effect(controller.signal,token);}),canceled]);
      return current(token)?result:null;
    }catch(error){
      if(current(token)){
        if(error?.status===401&&state.user)retire("Your login expired or was revoked.","personal");
        state={...state,error:safeFailure(error),phase:state.user?"authenticated":state.mode==="checking"?"error":"signed_out"};
        publish();
      }
      return null;
    }finally{
      clock.clearTimeout(deadline);controller.signal.removeEventListener("abort",abort);
      if(pending===controller)pending=null;
      if(current(token)){state={...state,busy:false};publish();}
    }
  }
  function deliver(kind,value) {
    if(!value||typeof value.code!=="string"||!value.code||value.code.length>1024||!Number.isSafeInteger(value.expires_at)||value.expires_at<=0)throw new Error("Invalid one-time response.");
    onOnce(Object.freeze({kind,value:value.code,expiresAt:value.expires_at}));
  }
  function page(value,kind) {
    if(!Array.isArray(value?.items)||value.items.length>100
      ||(value.next_cursor!==null&&value.next_cursor!==undefined&&(typeof value.next_cursor!=="string"||value.next_cursor.length>4096)))throw new Error("Invalid metadata response.");
    const items=kind==="users"?value.items.map(userView):value.items.map(token=>{
      if(typeof token?.id!=="string"||!token.id||(token.label!==null&&typeof token.label!=="string")
        ||token.label?.length>256||!Number.isSafeInteger(token.created_at)||!Number.isSafeInteger(token.expires_at)||typeof token.active!=="boolean")throw new Error("Invalid token metadata.");
      return Object.freeze({id:token.id,label:token.label,created_at:token.created_at,expires_at:token.expires_at,active:token.active});
    });
    return {items,cursor:value.next_cursor||null};
  }
  return {
    getSnapshot:snapshot,
    async start(){
      retire("Checking login availability.","checking");
      return run(async(signal,token)=>{
        const status=await api.getAuthStatus({signal});if(!current(token))return;
        if(!["legacy","personal","local_setup_required"].includes(status?.mode))throw new Error("Invalid authentication mode.");
        state={...state,mode:status.mode,phase:"signed_out",message:status.mode==="local_setup_required"
          ?"Set up the first owner from the Controller server.":status.mode==="legacy"?"Use the bootstrap token or set up the first owner.":"Sign in to Fleet."};
        if(status.mode==="personal"){
          try{const session=await api.getAdminSession({signal});if(current(token))activate(session);}
          catch(error){if(error?.status!==401)throw error;}
        }
      });
    },
    async login(username,password){
      retire("Signing in.","personal");
      return run(async(signal,token)=>{const result=await api.loginAdmin({username,password},{signal});if(current(token)){activate(result);return true;}});
    },
    async logout(){
      if(disposed||state.phase==="signing_out")return false;
      const proof=csrfToken;
      const wasBusy=state.busy;
      owner={};pending?.abort(new DOMException("Signing out.","AbortError"));pending=null;
      state={...state,busy:false,error:null,phase:"signing_out",message:"Signing out."};
      const result=await run(async(signal)=>{await api.logoutAdmin({},{csrfToken:proof,signal});return true;},{user:true});
      const error=state.error||(result===true?null:safeFailure({}));
      retire(error?"Server logout could not be confirmed. Close this page and ask an owner to revoke access.":wasBusy?"Signed out. A pending request may have completed; verify it after signing in. Running Agent jobs continue.":"Signed out. Running Agent jobs continue.","personal");
      if(error)state={...state,error};publish();return result!==null&&!error;
    },
    expire(){
      if(disposed)return;
      retire("Your login expired or was revoked. Sign in again.",state.mode==="legacy"?"legacy":"personal");publish();
    },
    suspend(){if(!disposed){retire("",state.mode);publish();}},
    async completeSetup(code,newPassword){
      retire("Setting password.","personal");
      return run(async(signal,token)=>{
        await api.completeAdminSetup({code,new_password:newPassword},{signal});
        if(current(token)){state={...state,phase:"signed_out",message:"Password ready. Sign in with your username."};return true;}
      });
    },
    async loadUsers({after}={}){
      return run(async(signal,token)=>{const value=page(await api.getAdminUsers({limit:25,after,signal}),"users");
        if(current(token)){state={...state,users:value.items,userCursor:value.cursor};return true;}},{user:true,ownerOnly:true});
    },
    async loadTokens({after}={}){
      return run(async(signal,token)=>{const value=page(await api.getAdminPersonalTokens({limit:25,after,signal}),"tokens");
        if(current(token)){state={...state,tokens:value.items,tokenCursor:value.cursor};return true;}},{user:true});
    },
    async createUser(input){
      return run(async(signal,token)=>{
        const result=await api.createAdminUser(input,{csrfToken,signal});
        if(current(token)){userView(result?.user);deliver("Account setup code",result.setup);state={...state,message:"Account created. Deliver the setup code privately; it is shown once."};return true;}
      },{user:true,ownerOnly:true});
    },
    async changeUser(id,input){
      return run(async(signal,token)=>{
        const result=await api.changeAdminUser(id,input,{csrfToken,signal});
        if(current(token)){const changed=userView(result?.user);
          if(changed.id===state.user.id&&(changed.role!==state.user.role||changed.status!=="active"))retire("Your account changed. Sign in again.","personal");
          else state={...state,user:changed.id===state.user.id?changed:state.user,message:"Account updated. Role changes or disabling revoke its existing logins and personal tokens."};
          publish();return true;}
      },{user:true,ownerOnly:true});
    },
    async resetUser(id,input){
      return run(async(signal,token)=>{
        const result=await api.resetAdminUserPassword(id,input,{csrfToken,signal});
        if(current(token)){
          if(id===state.user.id)retire("Your password was reset. Set a new password before signing in.","personal");
          deliver("Password reset code",result.reset);state={...state,message:"Password reset. Old logins and personal tokens were revoked. Deliver this code privately."};publish();return true;}
      },{user:true,ownerOnly:true});
    },
    async changePassword(input){
      return run(async(signal,token)=>{await api.changeOwnAdminPassword(input,{csrfToken,signal});
        if(current(token)){retire("Password changed. Sign in again; old logins and personal tokens were revoked.","personal");publish();return true;}},{user:true});
    },
    async createToken(input){
      return run(async(signal,token)=>{
        const result=await api.createAdminPersonalToken(input,{csrfToken,signal});
        if(current(token)){const value=result?.token;
          if(typeof value?.secret!=="string"||!value.secret||value.secret.length>1024||!Number.isSafeInteger(value.expires_at)||value.expires_at<=0)throw new Error("Invalid token response.");
          onOnce(Object.freeze({kind:"Personal CLI/API token",value:value.secret,expiresAt:value.expires_at}));
          state={...state,message:"Personal token created. It expires in 30 days and is shown once."};return true;}
      },{user:true});
    },
    async revokeToken(id){
      return run(async(signal,token)=>{await api.revokeAdminPersonalToken(id,{csrfToken,signal});
        if(current(token)){state={...state,message:"Personal token revoked."};return true;}},{user:true});
    },
    dispose(){if(disposed)return;retire();disposed=true;},
  };
}
