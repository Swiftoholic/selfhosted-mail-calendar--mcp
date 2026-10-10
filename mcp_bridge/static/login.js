"use strict";
const el = id => document.getElementById(id);
let state, busy = false;
const permissionNames={"bridge:read":"Geschützte Bridge verwenden","mail:read":"E-Mails lesen","contacts:read":"Namen, E-Mail-Adressen und Telefonnummern aus persönlich freigegebenen Adressbüchern lesen","mail:write":"E-Mails verschieben und markieren","mail:send":"E-Mails versenden","calendars:read":"Kalender lesen","calendars:write":"Termine in persönlich freigegebenen Kalendern verwalten","offline_access":"Dauerverbindung angefragt (zusätzliche Auswahl erforderlich)"};
const notice = text => { el("notice").textContent = text; };
const bytes = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
const encoded = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
async function status() {
  const r = await fetch("/auth/status", {cache:"no-store"});
  if (!r.ok) throw Error("request");
  const previousConsent=state?.pending_consent_id;
  state = await r.json();
  if(previousConsent!==state.pending_consent_id) el("persistent").checked=false;
  el("setup").hidden = state.configured;
  el("signin").hidden = !state.configured || (state.owner && state.recent_owner);
  el("owner").hidden = !state.owner;
  el("consent").hidden = !state.owner || !state.pending_scopes;
  el("persistent-option").hidden = !state.pending_refresh_available;
  if(!state.pending_refresh_available) el("persistent").checked=false;
  el("connections").hidden = !state.owner || !state.recent_owner;
  if (state.fingerprint) {
    el("request").hidden = false;
    el("fingerprint").textContent = state.fingerprint.match(/.{1,4}/g).join("-");
    el("register").disabled = !state.setup_approved || busy;
  }
  if (state.pending_scopes) {
    el("permissions").textContent = "Angefragte Rechte: " + state.pending_scopes.map(x=>permissionNames[x]||x).join(", ") + ".";
  }
  if(state.owner && state.recent_owner) await loadConnections();
  updateButtons();
}

function updateButtons() {
  document.querySelectorAll("button").forEach(button=>{
    const ownerAction=["approve","add","revoke"].includes(button.id)||button.classList.contains("revoke-connection");
    button.disabled=busy||(ownerAction&&!state?.recent_owner);
  });
  el("register").disabled=busy||!state?.setup_approved;
}
async function loadConnections() {
  const response=await fetch("/auth/grants",{cache:"no-store",credentials:"same-origin"});
  if(!response.ok) { el("connections").hidden=true;return; }
  const value=await response.json();
  el("connections-list").replaceChildren();
  el("connections-status").textContent=value.connections.length ? value.connections.length+" von 4 aktiven Verbindungen." : "Keine Dauerverbindung aktiv. Bestehende Freigaben ohne Dauerverbindung laufen nach 15 Minuten ab.";
  const date=value=>new Date(value*1000).toLocaleString("de-DE",{timeZone:"UTC"})+" UTC";
  value.connections.forEach(connection=>{
    const row=document.createElement("li"),heading=document.createElement("strong"),details=document.createElement("p"),scopes=document.createElement("p"),revoke=document.createElement("button");
    heading.textContent="ChatGPT · erlaubt am "+date(connection.created_at);
    details.textContent="Zuletzt erneuert: "+date(connection.last_used_at)+". Ohne weitere Erneuerung bis "+date(connection.idle_expires_at)+"; spätestens bis "+date(connection.absolute_expires_at)+".";
    scopes.textContent="Rechte: "+connection.scope.split(" ").filter(scope=>scope!=="offline_access").map(scope=>permissionNames[scope]||scope).join(", ")+".";
    revoke.textContent="Diese Verbindung sofort widerrufen";revoke.className="secondary revoke-connection";
    revoke.addEventListener("click",()=>runWork(async()=>{await action("grants/revoke",{grant_id:connection.id});notice("Diese Dauerverbindung und ihre Zugriffstokens wurden widerrufen.");}));
    row.append(heading,details,scopes,revoke);el("connections-list").append(row);
  });
}
async function action(path, body={}) {
  const r = await fetch("/auth/" + path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({...body,csrf:state.csrf}), cache:"no-store"});
  if (!r.ok) throw Error("request");
  return await r.json();
}
function options(value) {
  value.challenge = bytes(value.challenge);
  if (value.user) value.user.id = bytes(value.user.id);
  for (const list of [value.excludeCredentials,value.allowCredentials]) if(list) list.forEach(c=>c.id=bytes(c.id));
  return {publicKey:value};
}
function credential(value) {
  const response={clientDataJSON:encoded(value.response.clientDataJSON)};
  for(const field of ["attestationObject","authenticatorData","signature","userHandle"]) if(value.response[field]) response[field]=encoded(value.response[field]);
  if(value.response.getTransports) response.transports=value.response.getTransports();
  return {id:value.id,rawId:encoded(value.rawId),type:value.type,response,clientExtensionResults:value.getClientExtensionResults()};
}
async function register() {
  const value=await action("register/options");
  const result=await navigator.credentials.create(options(value));
  if(!result) throw Error("cancelled");
  await action("register/verify",{credential:credential(result)});
  notice("Passkey bestätigt. Du bist angemeldet.");
}
async function authenticate() {
  const value=await action("login/options");
  const result=await navigator.credentials.get(options(value));
  if(!result) throw Error("cancelled");
  await action("login/verify",{credential:credential(result)});
  notice("Passkey bestätigt. Prüfe eine angezeigte App-Freigabe vor dem Erlauben.");
}
async function runWork(work) {
    if(busy) return;
    busy=true;
    updateButtons();
    try { await work(); await status(); }
    catch (_) { notice("Anfrage nicht bestätigt. Versuche es erneut; für die Einrichtung muss genau diese Browser-Anfrage per SSH bestätigt sein. Für weitere Passkeys oder Freigaben melde dich gegebenenfalls erneut an."); }
    finally {busy=false;updateButtons();}
}
function button(id, work) {
  el(id).addEventListener("click",()=>runWork(work));
}
button("prepare",async()=>{await action("setup/request");notice("Bestätige jetzt den Fingerabdruck selbst per SSH. Hier wird kein Passwort benötigt.");});
button("register",register);button("add",register);button("authenticate",authenticate);
button("logout",async()=>{await action("logout");notice("Du bist abgemeldet. Bestehende App-Freigaben kannst du mit der Widerruf-Funktion beenden.");});
button("revoke",async()=>{await action("revoke");notice("Alle bisherigen App-Freigaben wurden widerrufen.");});
button("approve",async()=>{const r=await action("consent",{approve:true,consent_id:state.pending_consent_id,persistent:el("persistent").checked});const u=new URL(r.redirect);if(u.origin!=="https://chatgpt.com")throw Error("redirect");window.location.assign(u.href);});
status().then(()=>notice("Registriere deinen Passkey selbst. Diese Seite fordert keine GMX- oder Apple-Zugangsdaten an.")).catch(()=>notice("Der Anmeldedienst ist gerade nicht erreichbar."));
setInterval(()=>{if(!busy)status().catch(()=>{});},5000);
