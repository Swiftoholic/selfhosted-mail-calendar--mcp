"use strict";
const el = id => document.getElementById(id);
const i18n = window.BridgeI18n, t = (key, params) => i18n.t(key, params);
const scopes = {mail:["mail:read","mail:write","mail:send"], caldav:["calendars:read","calendars:write"], carddav:["contacts:read"]};
const manualIds = ["imap-host","imap-port","imap-tls","smtp-host","smtp-port","smtp-tls","dav-origin"];
let state=null, ready=false, busy=false, sequence=0, draft=null, step=1, epoch=0, controller=null, saving=false, removal=null;
let calendarAccount=null, calendarState=null, calendarReview=null, contactsAccount=null, contactsState=null, contactsReview=null;
const collectionEpoch={calendar:0,contacts:0}, messages=new Map();
function message(id, key="", params={}) {
  if(key) messages.set(id,{key,params}); else messages.delete(id);
  el(id).textContent=key?t(key,params):"";
}
function rawMessage(id, text) { messages.delete(id);el(id).textContent=text; }
function errorKey(code, fallback="error.generic") { return i18n.has("error."+code)?"error."+code:fallback; }
function selectedProfile() { return state?.profile_choices.find(x=>x.id===el("account-profile").value); }
function supportedProfile() { const profile=selectedProfile();return !!profile && profile.supported!==false; }
function clearSecrets() { el("account-password").value=""; }
function clearTest() { if(draft){draft.check=null;draft.review=null;}el("account-persist").checked=false;buttons(); }
function cancelWizard(key="") {
  epoch++; if(controller && !saving) controller.abort(); controller=null;
  draft=null;clearSecrets();el("wizard").reset();el("account-capabilities").replaceChildren();
  el("wizard-panel").hidden=true;message("wizard-result");message("review-summary");message("review-servers");
  if(key) message("account-result",key);
}
function clearCollection(kind) {
  collectionEpoch[kind]++;
  if(kind==="calendar") {calendarState=null;calendarReview=null;} else {contactsState=null;contactsReview=null;}
  el(kind+"-list").replaceChildren();el(kind+"-review").reset();el(kind+"-review").hidden=true;
}
function gate() {
  ready=false;state=null;sequence++;cancelWizard();removal=null;
  calendarAccount=null;contactsAccount=null;clearCollection("calendar");clearCollection("contacts");
  el("account-list").replaceChildren();el("workspace").hidden=true;el("renew").hidden=false;
  el("remove-review").hidden=true;el("remove-confirm").checked=false;
  message("notice","accounts.gated");buttons();
}
function buttons() {
  el("account-add").disabled=!ready || busy || state?.migration_required;
  el("account-list").querySelectorAll("button").forEach(button=>{button.disabled=!ready || busy || state?.migration_required;});
  ["wizard-next","wizard-check","wizard-save","remove-save","calendar-load","calendar-save","contacts-load","contacts-save"].forEach(id=>{el(id).disabled=!ready || busy;});
  ["wizard-back","wizard-cancel"].forEach(id=>{el(id).disabled=saving;});
  el("wizard").querySelectorAll("input").forEach(input=>{input.disabled=busy;});
  el("wizard").querySelectorAll("select").forEach(input=>{input.disabled=busy;});
  el("account-type").disabled=busy || !!draft?.row;el("account-profile").disabled=busy;
  const manual=!!selectedProfile()?.manual, protocol=el("account-type").value;
  manualIds.forEach(id=>{el(id).disabled=busy || !manual || (id==="dav-origin"?protocol==="mail":protocol!=="mail");});
  el("account-sender").disabled=busy || protocol!=="mail";
  ["calendar-cancel","contacts-cancel","remove-cancel"].forEach(id=>{el(id).disabled=busy;});
  el("remove-confirm").disabled=busy;el("language").disabled=busy;
  el("wizard-next").disabled=!ready || busy || !supportedProfile();
  el("wizard-check").disabled=!ready || busy || !supportedProfile();
  el("wizard-save").disabled=!ready || busy || !supportedProfile() || !draft?.check || !el("account-persist").checked;
  el("remove-save").disabled=!ready || busy || !removal || !el("remove-confirm").checked;
  el("calendar-save").disabled=!ready || busy || !calendarReview || calendarReview.write_permission==="denied";
  el("contacts-save").disabled=!ready || busy || !contactsReview || !el("contacts-read-ack").checked;
  ["calendar-list","contacts-list"].forEach(id=>el(id).querySelectorAll("button").forEach(button=>{button.disabled=!ready || busy;}));
}
function badge(row) {
  const key="connection."+row.connection.state;
  const status=t(i18n.has(key)?key:"connection.unknown"), checked=row.connection.checked_at;
  return typeof checked==="number" && Number.isFinite(checked)?t("connection.checkedAt",{status,date:i18n.date(checked)}):status;
}
function renderAccounts() {
  el("account-list").replaceChildren();el("account-empty").hidden=state.items.length!==0;
  for(const row of state.items) {
    const item=document.createElement("div");item.className="account-row";
    const info=document.createElement("div"),name=document.createElement("strong"),detail=document.createElement("span"),status=document.createElement("span"),rights=document.createElement("span");
    name.textContent=row.label;detail.textContent=t("type."+row.protocol)+" · "+(row.profile_id==="manual:"+row.protocol?t("provider.manualName"):row.provider)+" · "+row.username;detail.className="help";
    status.textContent=badge(row);status.className="badge";rights.textContent=t("accounts.rights",{rights:row.capabilities.map(x=>i18n.scope(x)).join(", ") || t("accounts.noRights")});rights.className="help";
    info.append(name,detail,status,rights);item.append(info);
    const actions=document.createElement("div");actions.className="actions";
    function action(key,fn) {const b=document.createElement("button");b.type="button";b.className="secondary";b.textContent=t(key);b.addEventListener("click",fn);actions.append(b);}
    action("accounts.editAction",()=>openWizard(row));
    action("accounts.testAgain",()=>run(async()=>{const result=await request("/accounts/manage/retest",{provider:row.protocol,account_id:row.id,expected_revision:row.revision});if(result){await accountStatus();message("account-result",result.connected?"accounts.checked":"error.connection_check_failed");}}));
    if(row.protocol!=="mail") action(row.protocol==="caldav"?"calendar.title":"contacts.title",()=>selectCollection(row));
    action("accounts.removeAction",()=>{cancelWizard();removal=row;el("remove-confirm").checked=false;rawMessage("remove-name",row.label+" · "+row.username);el("remove-review").hidden=false;buttons();});
    item.append(actions);el("account-list").append(item);
  }
  buttons();
}
async function accountStatus() {
  const current=++sequence;
  try {
    const authResponse=await fetch("/auth/status",{credentials:"same-origin",cache:"no-store"});
    if(!authResponse.ok){if(current===sequence)gate();return;}
    const auth=await authResponse.json();if(current!==sequence)return;
    if(!auth.owner || !auth.recent_owner){gate();return;}
    const response=await fetch("/accounts/status",{credentials:"same-origin",cache:"no-store"});
    if(current!==sequence)return;
    if(response.status===401){gate();return;}
    if(!response.ok){message("notice","accounts.unavailable");return;}
    const next=await response.json();if(current!==sequence)return;
    if(draft?.row && !next.items.some(row=>row.id===draft.row.id && row.revision===draft.row.revision)) cancelWizard("error.account_changed_reload_form");
    for(const [kind,row] of [["calendar",calendarAccount],["contacts",contactsAccount]]) if(row && !next.items.some(x=>x.id===row.id && x.revision===row.revision)) {clearCollection(kind);el(kind+"-access").hidden=true;if(kind==="calendar")calendarAccount=null;else contactsAccount=null;}
    state={...next,csrf:auth.csrf};ready=true;el("workspace").hidden=false;el("renew").hidden=true;
    message("notice",next.migration_required?"error.account_migration_required":"accounts.ready");renderAccounts();
  } catch(_) {message("notice","accounts.offline");}
}
async function request(path,payload,signal) {
  if(!ready) return null;
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",cache:"no-store",body:JSON.stringify({...payload,csrf:state.csrf}),...(signal?{signal}:{})});
  const result=await response.json();if(response.status===401){gate();return null;}
  if(!response.ok) throw Object.assign(new Error("request_rejected"),{code:result.error});
  return result;
}
async function run(fn,target="account-result") {
  if(!ready || busy)return;
  busy=true;sequence++;buttons();
  try {await fn();}catch(error){message(target,errorKey(error.code,"error.unavailable"));}
  finally{busy=false;buttons();}
}
function profiles() {
  const protocol=el("account-type").value,old=el("account-profile").value;el("account-profile").replaceChildren();
  const empty=document.createElement("option");empty.value="";empty.textContent=t("wizard.chooseProvider");el("account-profile").append(empty);
  for(const profile of state.profile_choices.filter(x=>x.protocol===protocol)) {
    const option=document.createElement("option");option.value=profile.id;
    option.textContent=(profile.manual?t("provider.manualName"):profile.name)+(profile.supported===false && profile.auth_mode==="oauth_required"?" · "+t("provider.unsupportedSuffix"):"");
    el("account-profile").append(option);
  }
  el("account-profile").value=state.profile_choices.some(x=>x.id===old && x.protocol===protocol)?old:"";
  profileDescription();
}
function providerLinks(id,profile) {
  const box=el(id);box.replaceChildren();
  const urls=[profile?.auth_help_url,...(profile?.source_urls || [])].filter((value,index,all)=>typeof value==="string" && all.indexOf(value)===index);
  for(const value of urls) {
    let url;try{url=new URL(value);}catch(_){continue;}
    if(url.protocol!=="https:" || url.username || url.password)continue;
    const link=document.createElement("a");link.href=url.href;link.target="_blank";link.rel="noopener noreferrer";link.textContent=t("provider.documentation");
    box.append(link);
  }
}
function profileDescription() {
  const profile=selectedProfile();
  if(!profile) message("profile-description","provider.chooseHelp");
  else if(profile.manual) message("profile-description","manual.help");
  else if(profile.protocol==="mail" && profile.imap_host && profile.smtp_host) message("profile-description","provider.servers",{servers:profile.imap_host+" / "+profile.smtp_host});
  else if(profile.origin) message("profile-description","provider.servers",{servers:profile.origin});
  else message("profile-description");
  const key=profile && i18n.has(profile.info_key)?profile.info_key:"provider.generic";
  message("profile-note",key);message("password-provider-note",key);
  el("profile-note").className=profile?.supported===false?"warning":"help";
  message("profile-verification",profile?.verification==="documented_not_live_tested"?"provider.notTested":"");
  providerLinks("profile-sources",profile);providerLinks("password-provider-sources",profile);
  updateManualVisibility();updatePasswordRules();buttons();
}
function updateManualVisibility() {
  const manual=!!selectedProfile()?.manual, mail=el("account-type").value==="mail";
  el("manual-servers").hidden=!manual;el("manual-mail").hidden=!mail;el("manual-dav").hidden=mail;
  el("imap-host").required=manual && mail;el("smtp-host").required=manual && mail;el("dav-origin").required=manual && !mail;
}
function resetServerFields(config=null) {
  el("imap-host").value=config?.imap?.host || "";el("imap-port").value=String(config?.imap?.port || 993);el("imap-tls").value=config?.imap?.tls || "implicit";
  el("smtp-host").value=config?.smtp?.host || "";el("smtp-port").value=String(config?.smtp?.port || 465);el("smtp-tls").value=config?.smtp?.tls || "implicit";
  el("dav-origin").value=config?.origin || "";
}
function invalidServer() { throw Object.assign(new Error("invalid_manual_server"),{code:"invalid_manual_server_config"}); }
function publicDnsName(value) {
  const host=value.trim().toLowerCase();
  if(host.length>253 || !host.includes(".") || /^[0-9.]+$/.test(host) || /\.(localhost|local|lan|internal|home|invalid|test|onion)$/.test(host) ||
    !host.split(".").every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))invalidServer();
  return host;
}
function serverConfig() {
  if(!selectedProfile()?.manual)return null;
  if(el("account-type").value==="mail") {
    const imap={host:publicDnsName(el("imap-host").value),port:Number(el("imap-port").value),tls:el("imap-tls").value};
    const smtp={host:publicDnsName(el("smtp-host").value),port:Number(el("smtp-port").value),tls:el("smtp-tls").value};
    if(imap.port!==993 || imap.tls!=="implicit" || !(smtp.port===465 && smtp.tls==="implicit" || smtp.port===587 && smtp.tls==="starttls_required"))invalidServer();
    return {preset:"custom",imap,smtp};
  }
  const raw=el("dav-origin").value.trim();let url;
  try{if(!/^https:\/\//i.test(raw) || /[\\\x00-\x20]/.test(raw))invalidServer();url=new URL(raw);}catch(_){invalidServer();}
  if(url.protocol!=="https:" || url.username || url.password || url.search || url.hash || !["","443","8443"].includes(url.port))invalidServer();
  const host=publicDnsName(url.hostname);
  return {preset:"custom",origin:url.href,allowed_hosts:[host]};
}
function changedServers() {
  if(!draft?.row)return true;
  if(draft.row.profile_id!==el("account-profile").value)return true;
  if(!selectedProfile()?.manual)return false;
  const canonical=value=>Array.isArray(value)?value.map(canonical):value && typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
  try{return JSON.stringify(canonical(serverConfig()))!==JSON.stringify(canonical(draft.row.server_config));}catch(_){return true;}
}
function updatePasswordRules() {
  if(!draft)return;
  const changed=changedServers();el("account-password").required=!draft.row || changed;
  message("password-help",!draft.row?"wizard.passwordNew":changed?"wizard.passwordChanged":"wizard.passwordKeep");
}
function drawStep() {
  el("wizard-provider").hidden=step!==1;el("wizard-details").hidden=step!==2;el("wizard-review").hidden=step!==3;
  el("wizard-next").hidden=step!==1;el("wizard-check").hidden=step!==2;el("wizard-save").hidden=step!==3;el("wizard-back").hidden=step===1;
  rawMessage("wizard-step-label",step+" / 3");buttons();
}
function openWizard(row=null) {
  if(!ready || busy || state.migration_required)return;
  cancelWizard();el("remove-review").hidden=true;removal=null;
  draft={row,check:null,review:null};step=1;el("wizard-panel").hidden=false;
  message("wizard-title",row?"accounts.edit":"accounts.add");el("account-type").value=row?.protocol || "mail";el("account-type").disabled=!!row;
  profiles();el("account-profile").value=row?.profile_id || "";resetServerFields(row?.server_config);profileDescription();
  el("account-label").value=row?.label || "";el("account-user").value=row?.username || "";el("account-sender").value=row?.sender_email || "";drawStep();
}
function details() {
  const protocol=el("account-type").value;
  el("sender-label").hidden=protocol!=="mail";el("account-sender").hidden=protocol!=="mail";el("account-sender").required=protocol==="mail";
  updateManualVisibility();updatePasswordRules();
  const selected=draft.row?.capabilities || [];el("account-capabilities").replaceChildren();
  for(const scope of scopes[protocol]) {
    const item=document.createElement("label"),input=document.createElement("input"),text=document.createElement("span");item.className="confirm";
    input.type="checkbox";input.value=scope;input.checked=selected.includes(scope);input.addEventListener("change",clearTest);text.textContent=i18n.scope(scope);
    item.append(input,text);el("account-capabilities").append(item);
  }
}
function candidate() {
  if(!supportedProfile()) throw Object.assign(new Error("unsupported_provider"),{code:"provider_oauth_not_supported"});
  return {provider:el("account-type").value,account_id:draft.row?.id || null,expected_revision:draft.row?.revision || null,
    profile_id:el("account-profile").value,server_config:serverConfig(),label:el("account-label").value,username:el("account-user").value,
    app_password:el("account-password").value || null,sender_email:el("account-type").value==="mail"?el("account-sender").value:null,
    capabilities:Array.from(el("account-capabilities").querySelectorAll("input")).filter(input=>input.checked).map(input=>input.value)};
}
async function inputFingerprint(payload) {
  const bytes=new TextEncoder().encode(JSON.stringify(payload));
  try{return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))).map(x=>x.toString(16).padStart(2,"0")).join("");}
  finally{bytes.fill(0);}
}
function serverSummary(config,profile=selectedProfile()) {
  if(config?.imap)return config.imap.host+":"+config.imap.port+" (TLS) / "+config.smtp.host+":"+config.smtp.port+" ("+(config.smtp.tls==="starttls_required"?"STARTTLS":"TLS")+")";
  return config?.origin || (profile?.protocol==="mail"?[profile.imap_host,profile.smtp_host].filter(Boolean).join(" / "):profile?.origin || "");
}
function renderReview() {
  if(!draft?.review)return;
  const review=draft.review;
  message("review-summary","wizard.review",{label:review.label,type:t("type."+review.protocol),username:review.username,rights:review.capabilities.map(x=>i18n.scope(x)).join(", ") || t("accounts.noRights")});
  const servers=serverSummary(review.server_config);message("review-servers",servers?"wizard.reviewServers":"",{servers});
}
async function checkWizard() {
  if(!draft || busy || !ready)return;
  if(!supportedProfile()){message("wizard-result","error.provider_oauth_not_supported");return;}
  updatePasswordRules();
  let payload=null;
  try{payload=candidate();}catch(error){message("wizard-result",errorKey(error.code));return;}
  if(!el("wizard").reportValidity()){payload.app_password=null;return;}
  busy=true;sequence++;const current=epoch;controller=new AbortController();buttons();clearTest();
  try {
    const result=await request("/accounts/manage/check",payload,controller.signal);if(current!==epoch || !draft || !result)return;
    const fingerprint=await inputFingerprint(payload);if(current!==epoch || !draft)return;
    if(!result.connected || !result.check_id){message("wizard-result","error.connection_check_failed");return;}
    draft.check={id:result.check_id,fingerprint};draft.review={label:payload.label,protocol:payload.provider,username:payload.username,capabilities:payload.capabilities,server_config:payload.server_config};step=3;
    renderReview();message("wizard-result","wizard.checked");drawStep();
  } catch(error) {if(current===epoch && draft)message("wizard-result",errorKey(error.code,"wizard.checkFailed"));}
  finally{if(payload){payload.app_password=null;payload=null;}if(current===epoch)controller=null;busy=false;buttons();}
}
async function saveWizard() {
  if(!ready || !draft?.check || busy || !el("account-persist").checked || !supportedProfile())return;
  let payload=null;saving=true;
  await run(async()=>{
    payload=candidate();const fingerprint=await inputFingerprint(payload);
    if(!draft?.check || fingerprint!==draft.check.fingerprint){clearTest();step=2;message("wizard-result","error.connection_check_required_or_changed");drawStep();return;}
    const result=await request("/accounts/manage/save",{...payload,check_id:draft.check.id,persistent_storage_confirmed:true});
    if(result){saving=false;cancelWizard();await accountStatus();message("account-result","accounts.saved");}
  },"wizard-result");
  if(payload)payload.app_password=null;saving=false;clearSecrets();clearTest();if(draft){step=2;drawStep();}buttons();
}
function selectCollection(row) {
  if(busy || !ready)return;
  const kind=row.protocol==="caldav"?"calendar":"contacts";
  if(kind==="calendar")calendarAccount=row;else contactsAccount=row;
  clearCollection(kind);rawMessage(kind+"-account",row.label+" · "+row.username);message(kind+"-result");el(kind+"-access").hidden=false;buttons();
}
async function collectionRequest(kind,action,payload={}) {
  const row=kind==="calendar"?calendarAccount:contactsAccount;
  if(!row || !ready)return null;
  return request("/accounts/"+(kind==="calendar"?"calendars":"contacts")+"/"+action,{...payload,account_id:row.id});
}
function collectionContext(kind) {
  const row=kind==="calendar"?calendarAccount:contactsAccount;
  return row?{id:row.id,revision:row.revision,epoch:collectionEpoch[kind]}:null;
}
function collectionCurrent(kind,context) {
  const row=kind==="calendar"?calendarAccount:contactsAccount;
  return ready && !!context && !!row && row.id===context.id && row.revision===context.revision && collectionEpoch[kind]===context.epoch;
}
function collectionPayload(kind,row) {const collection=kind==="calendar"?calendarState:contactsState;return {[kind==="calendar"?"calendar_id":"addressbook_id"]:row.id,expected_revision:collection.account_revision,expected_generation:row.generation};}
function renderCalendarReview() {
  if(!calendarReview)return;
  const review=calendarReview;rawMessage("calendar-review-name",review.calendar_name);
  message("calendar-audience",review.calendar_audience==="private_verified"?"calendar.private":review.calendar_audience==="shared_or_public"?"calendar.shared":"calendar.unknown");
  message("calendar-permission",review.write_permission==="denied"?"error.calendar_write_permission_denied":review.write_permission==="available"?"calendar.permissionAvailable":"calendar.permissionUnknown");
  message("calendar-warning","calendar.warning");el("calendar-warning").hidden=!review.requires_audience_acknowledgement;el("calendar-audience-label").hidden=!review.requires_audience_acknowledgement;
}
function renderCollection(kind) {
  const result=kind==="calendar"?calendarState:contactsState;if(!result)return;
  const context=collectionContext(kind);el(kind+"-list").replaceChildren();
  for(const row of result.items) {
    const item=document.createElement("div"),info=document.createElement("div"),name=document.createElement("strong"),status=document.createElement("span"),actions=document.createElement("div");item.className="calendar-row";actions.className="actions";
    name.textContent=row.name;status.textContent=t((kind==="calendar"?row.write_enabled:row.read_enabled)?"collection.active":"collection.inactive");status.className="badge";info.append(name,status);item.append(info);
    if(row.available_for_selection){
      const choose=document.createElement("button");choose.type="button";choose.className="secondary";choose.textContent=t("collection.review");
      choose.addEventListener("click",()=>run(async()=>{
        if(!collectionCurrent(kind,context))return;const payload=collectionPayload(kind,row);
        if(kind==="calendar"){
          const review=await collectionRequest(kind,"inspect",payload);if(!review || !collectionCurrent(kind,context))return;
          calendarReview={...review,payload};el("calendar-review").reset();renderCalendarReview();
        } else {contactsReview={payload};el("contacts-review").reset();rawMessage("contacts-review-name",row.name);}
        el(kind+"-review").hidden=false;
      },kind+"-result"));actions.append(choose);
    }
    if(kind==="calendar"?row.write_enabled:row.read_enabled){
      const revoke=document.createElement("button");revoke.type="button";revoke.className="secondary";revoke.textContent=t("collection.revoke");
      revoke.addEventListener("click",()=>run(async()=>{if(!collectionCurrent(kind,context))return;await collectionRequest(kind,"revoke",collectionPayload(kind,row));if(!collectionCurrent(kind,context))return;await loadCollection(kind);message(kind+"-result","collection.revoked");},kind+"-result"));actions.append(revoke);
    }
    item.append(actions);el(kind+"-list").append(item);
  }
  buttons();
}
async function loadCollection(kind) {
  const pending=collectionContext(kind),result=await collectionRequest(kind,"list");if(!result || !collectionCurrent(kind,pending))return;
  clearCollection(kind);if(kind==="calendar")calendarState=result;else contactsState=result;
  renderCollection(kind);message(kind+"-result",result.items.length?"collection.choose":"collection.empty");buttons();
}
el("account-add").addEventListener("click",()=>openWizard());
el("account-type").addEventListener("change",()=>{clearSecrets();clearTest();el("account-user").value="";el("account-sender").value="";resetServerFields();profiles();});
el("account-profile").addEventListener("change",()=>{clearSecrets();clearTest();resetServerFields(draft?.row?.profile_id===el("account-profile").value?draft.row.server_config:null);profileDescription();});
["account-label","account-user","account-sender","account-password"].forEach(id=>el(id).addEventListener("input",clearTest));
manualIds.forEach(id=>el(id).addEventListener(id.includes("host") || id==="dav-origin"?"input":"change",()=>{
  if(id==="smtp-port")el("smtp-tls").value=el(id).value==="587"?"starttls_required":"implicit";
  if(id==="smtp-tls")el("smtp-port").value=el(id).value==="starttls_required"?"587":"465";
  clearSecrets();clearTest();updatePasswordRules();
}));
el("wizard").addEventListener("submit",event=>event.preventDefault());
el("wizard-next").addEventListener("click",()=>{if(!draft || busy || !el("account-profile").reportValidity() || !supportedProfile())return;details();step=2;message("wizard-result");drawStep();});
el("wizard-back").addEventListener("click",()=>{if(!draft || saving)return;epoch++;if(controller)controller.abort();controller=null;clearSecrets();clearTest();step=Math.max(1,step-1);message("wizard-result");drawStep();});
el("wizard-cancel").addEventListener("click",()=>{if(!saving)cancelWizard();});
el("wizard-check").addEventListener("click",checkWizard);el("wizard-save").addEventListener("click",saveWizard);el("account-persist").addEventListener("change",buttons);
el("remove-confirm").addEventListener("change",buttons);el("remove-cancel").addEventListener("click",()=>{removal=null;el("remove-confirm").checked=false;el("remove-review").hidden=true;buttons();});
el("remove-save").addEventListener("click",()=>{
  if(!removal || !el("remove-confirm").checked)return;const row=removal;
  return run(async()=>{const result=await request("/accounts/manage/remove",{provider:row.protocol,account_id:row.id,expected_revision:row.revision,integration_removal_confirmed:true});if(result){removal=null;el("remove-review").hidden=true;await accountStatus();message("account-result","accounts.removed");}});
});
for(const kind of ["calendar","contacts"]){
  el(kind+"-load").addEventListener("click",()=>run(()=>loadCollection(kind),kind+"-result"));
  el(kind+"-cancel").addEventListener("click",()=>{if(kind==="calendar")calendarReview=null;else contactsReview=null;el(kind+"-review").reset();el(kind+"-review").hidden=true;buttons();});
}
el("calendar-save").addEventListener("click",()=>{
  if(!calendarReview || !el("calendar-capability-ack").checked || calendarReview.requires_audience_acknowledgement && !el("calendar-audience-ack").checked)return;
  const context=collectionContext("calendar"),payload={...calendarReview.payload,capability_only_acknowledged:true,audience_acknowledged:el("calendar-audience-ack").checked};
  return run(async()=>{await collectionRequest("calendar","save",payload);if(collectionCurrent("calendar",context))await loadCollection("calendar");},"calendar-result");
});
el("contacts-save").addEventListener("click",()=>{
  if(!contactsReview || !el("contacts-read-ack").checked)return;
  const context=collectionContext("contacts"),payload={...contactsReview.payload,read_access_acknowledged:true};
  return run(async()=>{await collectionRequest("contacts","save",payload);if(collectionCurrent("contacts",context))await loadCollection("contacts");},"contacts-result");
});
el("contacts-read-ack").addEventListener("change",buttons);
i18n.onChange(()=>{
  for(const [id,value] of messages)el(id).textContent=t(value.key,value.params);
  if(state)renderAccounts();
  if(draft){
    profiles();message("wizard-title",draft.row?"accounts.edit":"accounts.add");
    for(const label of el("account-capabilities").children)label.children[1].textContent=i18n.scope(label.children[0].value);
    renderReview();
  }
  renderCollection("calendar");renderCollection("contacts");renderCalendarReview();buttons();
});
window.addEventListener("keydown",event=>{if(event.key==="Escape" && !saving)cancelWizard();});
window.addEventListener("pagehide",()=>{clearSecrets();clearTest();});
window.addEventListener("focus",accountStatus);setInterval(accountStatus,30000);accountStatus();
