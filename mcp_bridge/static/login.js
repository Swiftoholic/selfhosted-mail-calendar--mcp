"use strict";
const el = id => document.getElementById(id);
const i18n=window.BridgeI18n,t=(key,params)=>i18n.t(key,params);
let state,busy=false,connections=null,noticeKey="login.loading";
function notice(key) {noticeKey=key;el("notice").textContent=t(key);}
const bytes = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
const encoded = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
function renderPermissions() {
  if(state?.pending_scopes)el("permissions").textContent=t("login.permissions",{rights:state.pending_scopes.map(scope=>i18n.scope(scope)).join(", ")});
}
async function status() {
  const r = await fetch("/auth/status", {cache:"no-store"});
  if (!r.ok) throw Error("request");
  const previousConsent=state?.pending_consent_id;
  state=await r.json();
  if(previousConsent!==state.pending_consent_id)el("persistent").checked=false;
  el("setup").hidden=state.configured;
  el("signin").hidden=!state.configured || (state.owner && state.recent_owner);
  el("owner").hidden=!state.owner;el("consent").hidden=!state.owner || !state.pending_scopes;
  el("persistent-option").hidden=!state.pending_refresh_available;
  if(!state.pending_refresh_available)el("persistent").checked=false;
  el("connections").hidden=!state.owner || !state.recent_owner;
  if(state.fingerprint) {
    el("request").hidden=false;el("fingerprint").textContent=state.fingerprint.match(/.{1,4}/g).join("-");
    el("register").disabled=!state.setup_approved || busy;
  }
  renderPermissions();
  if(state.owner && state.recent_owner)await loadConnections();
  else {connections=null;el("connections-list").replaceChildren();}
  updateButtons();
}
function updateButtons() {
  document.querySelectorAll("button").forEach(button=>{
    const ownerAction=["approve","add","revoke"].includes(button.id)||button.classList.contains("revoke-connection");
    button.disabled=busy||(ownerAction&&!state?.recent_owner);
  });
  el("register").disabled=busy||!state?.setup_approved;el("language").disabled=busy;
}
async function loadConnections() {
  const response=await fetch("/auth/grants",{cache:"no-store",credentials:"same-origin"});
  if(!response.ok){connections=null;el("connections").hidden=true;el("connections-list").replaceChildren();return;}
  connections=(await response.json()).connections;renderConnections();
}
function renderConnections() {
  el("connections-list").replaceChildren();if(!connections)return;
  el("connections-status").textContent=t(connections.length?"login.connectionsCount":"login.connectionsEmpty",{count:connections.length});
  const date=value=>i18n.date(value,{timeZone:"UTC"})+" UTC";
  for(const connection of connections) {
    const row=document.createElement("li"),heading=document.createElement("strong"),details=document.createElement("p"),scopes=document.createElement("p"),revoke=document.createElement("button");
    heading.textContent=t("login.connectionTitle",{date:date(connection.created_at)});
    details.textContent=t("login.connectionDates",{used:date(connection.last_used_at),idle:date(connection.idle_expires_at),absolute:date(connection.absolute_expires_at)});
    scopes.textContent=t("login.connectionScopes",{rights:connection.scope.split(" ").filter(scope=>scope!=="offline_access").map(scope=>i18n.scope(scope)).join(", ")});
    revoke.textContent=t("login.connectionRevoke");revoke.className="secondary revoke-connection";
    revoke.addEventListener("click",()=>runWork(async()=>{await action("grants/revoke",{grant_id:connection.id});notice("login.connectionRevoked");}));
    row.append(heading,details,scopes,revoke);el("connections-list").append(row);
  }
  updateButtons();
}
async function action(path,body={}) {
  const r=await fetch("/auth/"+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...body,csrf:state.csrf}),cache:"no-store"});
  if(!r.ok)throw Error("request");
  return await r.json();
}
function options(value) {
  value.challenge=bytes(value.challenge);
  if(value.user)value.user.id=bytes(value.user.id);
  for(const list of [value.excludeCredentials,value.allowCredentials])if(list)list.forEach(c=>c.id=bytes(c.id));
  return {publicKey:value};
}
function credential(value) {
  const response={clientDataJSON:encoded(value.response.clientDataJSON)};
  for(const field of ["attestationObject","authenticatorData","signature","userHandle"])if(value.response[field])response[field]=encoded(value.response[field]);
  if(value.response.getTransports)response.transports=value.response.getTransports();
  return {id:value.id,rawId:encoded(value.rawId),type:value.type,response,clientExtensionResults:value.getClientExtensionResults()};
}
async function register() {
  const value=await action("register/options"),result=await navigator.credentials.create(options(value));
  if(!result)throw Error("cancelled");
  await action("register/verify",{credential:credential(result)});notice("login.registered");
}
async function authenticate() {
  const value=await action("login/options"),result=await navigator.credentials.get(options(value));
  if(!result)throw Error("cancelled");
  await action("login/verify",{credential:credential(result)});notice("login.authenticated");
}
async function runWork(work) {
  if(busy)return;
  busy=true;updateButtons();
  try{await work();await status();}catch(_){notice("login.failed");}
  finally{busy=false;updateButtons();}
}
function button(id,work) {el(id).addEventListener("click",()=>runWork(work));}
button("prepare",async()=>{await action("setup/request");notice("login.prepared");});
button("register",register);button("add",register);button("authenticate",authenticate);
button("logout",async()=>{await action("logout");notice("login.loggedOut");});
button("revoke",async()=>{await action("revoke");notice("login.revoked");});
button("approve",async()=>{
  const r=await action("consent",{approve:true,consent_id:state.pending_consent_id,persistent:el("persistent").checked});
  const u=new URL(r.redirect);if(u.origin!=="https://chatgpt.com")throw Error("redirect");window.location.assign(u.href);
});
i18n.onChange(()=>{notice(noticeKey);renderPermissions();renderConnections();updateButtons();});
status().then(()=>notice("login.ready")).catch(()=>notice("login.offline"));
setInterval(()=>{if(!busy)status().catch(()=>{});},5000);