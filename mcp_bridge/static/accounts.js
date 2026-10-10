"use strict";
const el = id => document.getElementById(id);
const scopeLabels = {"mail:read":"Mails lesen", "mail:write":"Mails markieren und verschieben", "mail:send":"Mails versenden", "calendars:read":"Kalender lesen", "calendars:write":"Termine ändern", "contacts:read":"Ausgewählte Adressbücher lesen"};
const scopes = {mail:["mail:read","mail:write","mail:send"], caldav:["calendars:read","calendars:write"], carddav:["contacts:read"]};
const typeLabels = {mail:"Mail · IMAP / SMTP", caldav:"Kalender · CalDAV", carddav:"Kontakte · CardDAV"};
const errors = {account_selection_required:"Wähle ein bestimmtes Konto.", account_changed_reload_form:"Das Konto hat sich geändert. Lade den Status neu.", account_catalog_changed_reload:"Die Kontenliste hat sich geändert. Lade den Status neu.", provider_busy_try_again:"Dieses Konto wird gerade verwendet. Versuche es danach erneut.", connection_check_failed:"Prüfe Anmeldename, App-Passwort und Erreichbarkeit.", invalid_account_input:"Prüfe Anmeldename, Absenderadresse und App-Passwort.", invalid_account_label:"Gib einen Namen für das Konto ein.", invalid_account_capabilities:"Prüfe die ausgewählten Rechte.", profile_change_requires_password:"Für ein anderes Serverprofil musst du das App-Passwort erneut eingeben.", connection_check_required_or_changed:"Der Test ist abgelaufen oder die Eingabe hat sich geändert. Teste erneut.", account_save_unavailable_check_status:"Prüfe den Kontenstatus. Die Speicherung wird nicht automatisch wiederholt.", account_migration_required:"Die vorhandenen Konten müssen zuerst vom Betreiber übernommen werden.", provider_profile_changed_reenter_credentials:"Das Serverprofil hat sich geändert. Prüfe die Server und gib das App-Passwort erneut ein.", calendar_audience_acknowledgement_required:"Bestätige mögliche Sichtbarkeit und Benachrichtigungen für andere Mitglieder.", calendar_write_permission_denied:"Der Anbieter meldet keine Schreibberechtigung.", calendar_account_changed_reload:"Das Konto hat sich geändert. Lade die Kalender neu.", calendar_consent_changed_reload:"Die Freigabe hat sich geändert. Lade die Kalender neu.", contacts_account_changed_reload:"Das Konto hat sich geändert. Lade die Adressbücher neu.", contacts_consent_changed_reload:"Die Freigabe hat sich geändert. Lade die Adressbücher neu."};
let state=null, ready=false, busy=false, sequence=0, draft=null, step=1, epoch=0, controller=null, saving=false, removal=null;
let calendarAccount=null, calendarState=null, calendarReview=null, contactsAccount=null, contactsState=null, contactsReview=null;
const collectionEpoch={calendar:0,contacts:0};
function message(id, text) { el(id).textContent=text; }
function clearSecrets() { el("account-password").value=""; }
function clearTest() { if(draft) draft.check=null; el("account-persist").checked=false; }
function cancelWizard(text="") {
  epoch++; if(controller && !saving) controller.abort(); controller=null;
  draft=null; clearSecrets(); el("wizard").reset(); el("account-capabilities").replaceChildren();
  el("wizard-panel").hidden=true; message("wizard-result","");
  if(text) message("account-result",text);
}
function clearCollection(kind) {
  collectionEpoch[kind]++;
  if(kind==="calendar") {calendarState=null;calendarReview=null;} else {contactsState=null;contactsReview=null;}
  el(kind+"-list").replaceChildren(); el(kind+"-review").reset(); el(kind+"-review").hidden=true;
}
function gate() {
  ready=false; state=null; sequence++; cancelWizard(); removal=null;
  calendarAccount=null; contactsAccount=null; clearCollection("calendar"); clearCollection("contacts");
  el("account-list").replaceChildren(); el("workspace").hidden=true; el("renew").hidden=false;
  el("remove-review").hidden=true; el("remove-confirm").checked=false;
  message("notice","Melde dich erneut mit deinem Passkey an, um deine Konten zu verwalten."); buttons();
}
function buttons() {
  el("account-add").disabled=!ready || busy || state?.migration_required;
  el("account-list").querySelectorAll("button").forEach(button=>{button.disabled=!ready || busy || state?.migration_required;});
  ["wizard-next","wizard-check","wizard-save","remove-save","calendar-load","calendar-save","contacts-load","contacts-save"].forEach(id=>{el(id).disabled=!ready || busy;});
  ["wizard-back","wizard-cancel"].forEach(id=>{el(id).disabled=saving;});
  el("wizard").querySelectorAll("input").forEach(input=>{input.disabled=busy;});
  el("account-type").disabled=busy || !!draft?.row;el("account-profile").disabled=busy;
  ["calendar-cancel","contacts-cancel","remove-cancel"].forEach(id=>{el(id).disabled=busy;});
  el("remove-confirm").disabled=busy;
  el("wizard-save").disabled=!ready || busy || !draft?.check || !el("account-persist").checked;
  el("remove-save").disabled=!ready || busy || !removal || !el("remove-confirm").checked;
  el("calendar-save").disabled=!ready || busy || !calendarReview || calendarReview.write_permission==="denied";
  el("contacts-save").disabled=!ready || busy || !contactsReview;
  ["calendar-list","contacts-list"].forEach(id=>el(id).querySelectorAll("button").forEach(button=>{button.disabled=!ready || busy;}));
}
function badge(row) {
  const descriptions={never_checked:"Noch nicht geprüft", connected:"Verbindung geprüft", failed:"Verbindungstest fehlgeschlagen", profile_changed:"Serverprofil prüfen"};
  let text=descriptions[row.connection.state] || "Status unbekannt";
  if(row.connection.checked_at!==null) text+=" · "+new Date(row.connection.checked_at*1000).toLocaleString("de-DE");
  return text;
}
function renderAccounts() {
  el("account-list").replaceChildren(); el("account-empty").hidden=state.items.length!==0;
  for(const row of state.items) {
    const item=document.createElement("div");item.className="account-row";
    const info=document.createElement("div"), name=document.createElement("strong"), detail=document.createElement("span"), status=document.createElement("span"), rights=document.createElement("span");
    name.textContent=row.label;detail.textContent=typeLabels[row.protocol]+" · "+row.provider+" · "+row.username;detail.className="help";
    status.textContent=badge(row);status.className="badge";rights.textContent=row.capabilities.map(x=>scopeLabels[x]).join(", ") || "Kein KI-Zugriff freigegeben";rights.className="help";
    info.append(name,detail,status,rights);item.append(info);
    const actions=document.createElement("div");actions.className="actions";
    function action(text, fn) {const b=document.createElement("button");b.type="button";b.className="secondary";b.textContent=text;b.addEventListener("click",fn);actions.append(b);}
    action("Bearbeiten",()=>openWizard(row));action("Erneut testen",()=>run(async()=>{const result=await request("/accounts/manage/retest",{provider:row.protocol,account_id:row.id,expected_revision:row.revision}); if(result){await accountStatus();message("account-result",result.connected?"Verbindung erfolgreich geprüft.":errors.connection_check_failed);}}));
    if(row.protocol!=="mail") action(row.protocol==="caldav"?"Kalenderfreigaben":"Adressbuchfreigaben",()=>selectCollection(row));
    action("Entfernen",()=>{cancelWizard();removal=row;el("remove-confirm").checked=false;message("remove-name",row.label+" · "+row.username);el("remove-review").hidden=false;buttons();});
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
    if(!response.ok){message("notice","Kontenstatus nicht verfügbar. Lade die Seite erneut.");return;}
    const next=await response.json();if(current!==sequence)return;
    if(draft?.row && !next.items.some(row=>row.id===draft.row.id && row.revision===draft.row.revision)) cancelWizard(errors.account_changed_reload_form);
    for(const [kind,row] of [["calendar",calendarAccount],["contacts",contactsAccount]]) if(row && !next.items.some(x=>x.id===row.id && x.revision===row.revision)) {clearCollection(kind);el(kind+"-access").hidden=true;if(kind==="calendar")calendarAccount=null;else contactsAccount=null;}
    state={...next,csrf:auth.csrf};ready=true;el("workspace").hidden=false;el("renew").hidden=true;
    message("notice",next.migration_required?errors.account_migration_required:"Deine Konten sind sichtbar. Verbindungstests und Änderungen startest du selbst.");renderAccounts();
  } catch(_) {message("notice","Dienst nicht erreichbar. Lade den Kontenstatus erneut.");}
}
async function request(path,payload,signal) {
  if(!ready) return null;
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",cache:"no-store",body:JSON.stringify({...payload,csrf:state.csrf}),...(signal?{signal}:{})});
  const result=await response.json();if(response.status===401){gate();return null;}
  if(!response.ok) throw Object.assign(new Error(errors[result.error] || "Anfrage abgelehnt. Prüfe Sitzung und Eingabe."),{code:result.error});
  return result;
}
async function run(fn,target="account-result") {
  if(!ready || busy)return;
  busy=true;sequence++;buttons();
  try {await fn();}catch(error){message(target,errors[error.code] || "Dienst nicht erreichbar. Prüfe den Status; Änderungen werden nicht automatisch wiederholt.");}
  finally{busy=false;buttons();}
}
function profiles() {
  const protocol=el("account-type").value;
  const old=el("account-profile").value;el("account-profile").replaceChildren();
  const empty=document.createElement("option");empty.value="";empty.textContent="Anbieter auswählen";el("account-profile").append(empty);
  for(const profile of state.profile_choices.filter(x=>x.protocol===protocol)) {const option=document.createElement("option");option.value=profile.id;option.textContent=profile.name;el("account-profile").append(option);}
  el("account-profile").value=state.profile_choices.some(x=>x.id===old && x.protocol===protocol)?old:"";
  profileDescription();
}
function profileDescription() {
  const profile=state?.profile_choices.find(x=>x.id===el("account-profile").value);
  message("profile-description",profile?(profile.protocol==="mail"?profile.imap_host+" / "+profile.smtp_host:profile.origin):"Die Server werden vom Betreiber bereitgestellt.");
}
function drawStep() {
  el("wizard-provider").hidden=step!==1;el("wizard-details").hidden=step!==2;el("wizard-review").hidden=step!==3;
  el("wizard-next").hidden=step!==1;el("wizard-check").hidden=step!==2;el("wizard-save").hidden=step!==3;el("wizard-back").hidden=step===1;
  message("wizard-step-label",step+" / 3");buttons();
}
function openWizard(row=null) {
  if(!ready || busy || state.migration_required)return;
  cancelWizard();el("remove-review").hidden=true;removal=null;
  draft={row,check:null};step=1;el("wizard-panel").hidden=false;
  message("wizard-title",row?"Konto bearbeiten":"Konto hinzufügen");el("account-type").value=row?.protocol || "mail";el("account-type").disabled=!!row;
  profiles();el("account-profile").value=row?.profile_id || "";profileDescription();
  el("account-label").value=row?.label || "";el("account-user").value=row?.username || "";el("account-sender").value=row?.sender_email || "";drawStep();
}
function details() {
  const protocol=el("account-type").value;
  el("sender-label").hidden=protocol!=="mail";el("account-sender").hidden=protocol!=="mail";el("account-sender").required=protocol==="mail";
  el("account-password").required=!draft.row;
  message("password-help",draft.row?"Leer lassen, um das gespeicherte App-Passwort beizubehalten. Bei einem anderen Serverprofil erneut eingeben.":"Gib das App-Passwort nur hier ein. Es wird niemals zurückangezeigt.");
  const selected=draft.row?.capabilities || [];
  el("account-capabilities").replaceChildren();
  for(const scope of scopes[protocol]) {const item=document.createElement("label"),input=document.createElement("input"),text=document.createElement("span");item.className="confirm";input.type="checkbox";input.value=scope;input.checked=selected.includes(scope);input.addEventListener("change",clearTest);text.textContent=scopeLabels[scope];item.append(input,text);el("account-capabilities").append(item);}
}
function candidate() {
  return {provider:el("account-type").value,account_id:draft.row?.id || null,expected_revision:draft.row?.revision || null,
    profile_id:el("account-profile").value,label:el("account-label").value,username:el("account-user").value,
    app_password:el("account-password").value || null,sender_email:el("account-type").value==="mail"?el("account-sender").value:null,
    capabilities:Array.from(el("account-capabilities").querySelectorAll("input")).filter(input=>input.checked).map(input=>input.value)};
}
async function inputFingerprint(payload) {
  const bytes=new TextEncoder().encode(JSON.stringify(payload));
  try{return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))).map(x=>x.toString(16).padStart(2,"0")).join("");}
  finally{bytes.fill(0);}
}
async function checkWizard() {
  if(!draft || busy || !ready || !el("wizard").reportValidity())return;
  busy=true;sequence++;const current=epoch;controller=new AbortController();buttons();clearTest();
  let payload=null;
  try {payload=candidate();const result=await request("/accounts/manage/check",payload,controller.signal);if(current!==epoch || !draft || !result)return;
    const fingerprint=await inputFingerprint(payload);if(current!==epoch || !draft)return;
    draft.check={id:result.check_id,fingerprint};step=3;
    message("review-summary",payload.label+" · "+typeLabels[payload.provider]+" · "+payload.username+". Rechte: "+(payload.capabilities.map(x=>scopeLabels[x]).join(", ") || "kein KI-Zugriff"));
    message("wizard-result","Verbindung erfolgreich geprüft. Es wurde noch nichts gespeichert.");drawStep();
  } catch(error) {if(current===epoch && draft)message("wizard-result",errors[error.code] || "Test nicht abgeschlossen. Prüfe Eingabe und Sitzung.");}
  finally{if(payload){payload.app_password=null;payload=null;}if(current===epoch)controller=null;busy=false;buttons();}
}
async function saveWizard() {
  if(!draft?.check || busy || !el("account-persist").checked)return;
  let payload=null;saving=true;
  await run(async()=>{payload=candidate();const fingerprint=await inputFingerprint(payload);
    if(!draft?.check || fingerprint!==draft.check.fingerprint){clearTest();step=2;message("wizard-result",errors.connection_check_required_or_changed);drawStep();return;}
    const result=await request("/accounts/manage/save",{...payload,check_id:draft.check.id,persistent_storage_confirmed:true});
    if(result){saving=false;cancelWizard();await accountStatus();message("account-result","Konto gespeichert. Seine Kalender und Adressbücher kannst du einzeln freigeben.");}
  },"wizard-result");
  if(payload)payload.app_password=null;saving=false;clearSecrets();clearTest();if(draft){step=2;drawStep();}buttons();
}
function selectCollection(row) {
  if(busy || !ready)return;
  const kind=row.protocol==="caldav"?"calendar":"contacts";
  if(kind==="calendar")calendarAccount=row;else contactsAccount=row;
  clearCollection(kind);message(kind+"-account",row.label+" · "+row.username);message(kind+"-result","");el(kind+"-access").hidden=false;buttons();
}
async function collectionRequest(kind, action, payload={}) {
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
async function loadCollection(kind) {
  const pending=collectionContext(kind),result=await collectionRequest(kind,"list");if(!result || !collectionCurrent(kind,pending))return;
  clearCollection(kind);if(kind==="calendar")calendarState=result;else contactsState=result;
  const context=collectionContext(kind);
  for(const row of result.items) {
    const item=document.createElement("div"),info=document.createElement("div"),name=document.createElement("strong"),status=document.createElement("span"),actions=document.createElement("div");item.className="calendar-row";actions.className="actions";
    name.textContent=row.name;status.textContent=(kind==="calendar"?row.write_enabled:row.read_enabled)?"Freigabe aktiv":"Freigabe aus";status.className="badge";info.append(name,status);item.append(info);
    if(row.available_for_selection){const choose=document.createElement("button");choose.type="button";choose.className="secondary";choose.textContent="Freigabe prüfen";
      choose.addEventListener("click",()=>run(async()=>{if(!collectionCurrent(kind,context))return;const payload=collectionPayload(kind,row);
        if(kind==="calendar"){const review=await collectionRequest(kind,"inspect",payload);if(!review || !collectionCurrent(kind,context))return;calendarReview={...review,payload};el("calendar-review").reset();message("calendar-review-name",review.calendar_name);
          message("calendar-audience",review.calendar_audience==="private_verified"?"Anbieter-Metadaten bestätigen Zugriff nur für den Eigentümer.":review.calendar_audience==="shared_or_public"?"Der Anbieter meldet eine Freigabe für andere.":"Die Sichtbarkeit konnte nicht bestätigt werden.");message("calendar-permission",review.write_permission==="denied"?errors.calendar_write_permission_denied:review.write_permission==="available"?"Der Anbieter meldet Schreibrechte.":"Schreibrechte sind unbekannt; der Anbieter kann Änderungen ablehnen.");message("calendar-warning",review.audience_warning);el("calendar-warning").hidden=!review.requires_audience_acknowledgement;el("calendar-audience-label").hidden=!review.requires_audience_acknowledgement;
        }else{contactsReview={payload};el("contacts-review").reset();message("contacts-review-name",row.name);}el(kind+"-review").hidden=false;
      },kind+"-result"));actions.append(choose);}
    if(kind==="calendar"?row.write_enabled:row.read_enabled){const revoke=document.createElement("button");revoke.type="button";revoke.className="secondary";revoke.textContent="Freigabe widerrufen";revoke.addEventListener("click",()=>run(async()=>{if(!collectionCurrent(kind,context))return;await collectionRequest(kind,"revoke",collectionPayload(kind,row));if(!collectionCurrent(kind,context))return;await loadCollection(kind);message(kind+"-result","Freigabe widerrufen. Daten beim Anbieter bleiben bestehen.");},kind+"-result"));actions.append(revoke);}
    item.append(actions);el(kind+"-list").append(item);
  }
  message(kind+"-result",result.items.length?"Wähle die Freigaben für dieses Konto.":"Keine Kalender oder Adressbücher gefunden.");buttons();
}
el("account-add").addEventListener("click",()=>openWizard());
el("account-type").addEventListener("change",()=>{clearSecrets();clearTest();el("account-user").value="";el("account-sender").value="";profiles();});
el("account-profile").addEventListener("change",()=>{clearSecrets();clearTest();profileDescription();});
["account-label","account-user","account-sender","account-password"].forEach(id=>el(id).addEventListener("input",clearTest));
el("wizard").addEventListener("submit",event=>event.preventDefault());
el("wizard-next").addEventListener("click",()=>{if(!draft || busy || !el("account-profile").reportValidity())return;details();step=2;message("wizard-result","");drawStep();});
el("wizard-back").addEventListener("click",()=>{if(!draft || saving)return;epoch++;if(controller)controller.abort();controller=null;clearSecrets();clearTest();step=Math.max(1,step-1);message("wizard-result","");drawStep();});
el("wizard-cancel").addEventListener("click",()=>{if(!saving)cancelWizard();});el("wizard-check").addEventListener("click",checkWizard);el("wizard-save").addEventListener("click",saveWizard);el("account-persist").addEventListener("change",buttons);
el("remove-confirm").addEventListener("change",buttons);el("remove-cancel").addEventListener("click",()=>{removal=null;el("remove-confirm").checked=false;el("remove-review").hidden=true;buttons();});
el("remove-save").addEventListener("click",()=>{if(!removal || !el("remove-confirm").checked)return;const row=removal;return run(async()=>{const result=await request("/accounts/manage/remove",{provider:row.protocol,account_id:row.id,expected_revision:row.revision,integration_removal_confirmed:true});if(result){removal=null;el("remove-review").hidden=true;await accountStatus();message("account-result","Anbindung entfernt. Daten beim Anbieter bleiben bestehen.");}});});
for(const kind of ["calendar","contacts"]){el(kind+"-load").addEventListener("click",()=>run(()=>loadCollection(kind),kind+"-result"));el(kind+"-cancel").addEventListener("click",()=>{if(kind==="calendar")calendarReview=null;else contactsReview=null;el(kind+"-review").reset();el(kind+"-review").hidden=true;buttons();});}
el("calendar-save").addEventListener("click",()=>{if(!calendarReview || !el("calendar-capability-ack").checked || calendarReview.requires_audience_acknowledgement && !el("calendar-audience-ack").checked)return;const context=collectionContext("calendar"),payload={...calendarReview.payload,capability_only_acknowledged:true,audience_acknowledged:el("calendar-audience-ack").checked};return run(async()=>{await collectionRequest("calendar","save",payload);if(collectionCurrent("calendar",context))await loadCollection("calendar");},"calendar-result");});
el("contacts-save").addEventListener("click",()=>{if(!contactsReview || !el("contacts-read-ack").checked)return;const context=collectionContext("contacts"),payload={...contactsReview.payload,read_access_acknowledged:true};return run(async()=>{await collectionRequest("contacts","save",payload);if(collectionCurrent("contacts",context))await loadCollection("contacts");},"contacts-result");});
window.addEventListener("keydown",event=>{if(event.key==="Escape" && !saving)cancelWizard();});
window.addEventListener("pagehide",()=>{clearSecrets();clearTest();});
window.addEventListener("focus",accountStatus);setInterval(accountStatus,30000);accountStatus();
