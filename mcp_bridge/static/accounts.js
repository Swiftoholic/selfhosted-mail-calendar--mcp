"use strict";
const accountEl = id => document.getElementById(id);
const providers = ["mail", "caldav", "carddav"];
let accountState = null, accountBusy = false, accountReady = false, accountStatusSequence = 0;
let calendarState = null, calendarReview = null;
let contactsState = null, contactsReview = null;
const accountNotice = text => { accountEl("notice").textContent = text; };
function calendarCancel() {
  calendarReview = null;
  accountEl("calendar-review").reset();
  accountEl("calendar-review").hidden = true;
  accountEl("calendar-review-name").textContent = "";
  accountEl("calendar-review-id").textContent = "";
}
function calendarClear() {
  calendarState = null;
  calendarCancel();
  accountEl("calendar-list").replaceChildren();
}
function accountGate() {
  accountReady = false; accountState = null; calendarClear(); contactsClear();
  providers.forEach(provider => accountEl(provider).reset());
  accountEl("forms").hidden = true; accountEl("calendar-access").hidden = true; accountEl("contacts-access").hidden = true;
  accountEl("renew").hidden = false;
  accountNotice("Deine Freigabe ist abgelaufen. Melde dich erneut mit deinem Passkey an.");
  accountButtons();
}
function accountButtons() {
  providers.forEach(provider => ["check", "save"].forEach(action => {
    accountEl(provider + "-" + action).disabled = !accountReady || accountBusy;
  }));
  accountEl("calendar-load").disabled = !accountReady || accountBusy || !accountState?.accounts.caldav.configured;
  accountEl("calendar-save").disabled = !accountReady || accountBusy || !calendarReview || calendarReview.write_permission === "denied";
  accountEl("calendar-cancel").disabled = accountBusy;
  accountEl("calendar-list").querySelectorAll("button").forEach(button => { button.disabled = !accountReady || accountBusy; });
  accountEl("contacts-load").disabled = !accountReady || accountBusy || !accountState?.accounts.carddav.configured;
  accountEl("contacts-save").disabled = !accountReady || accountBusy || !contactsReview;
  accountEl("contacts-cancel").disabled = accountBusy;
  accountEl("contacts-list").querySelectorAll("button").forEach(button => { button.disabled = !accountReady || accountBusy; });
}
async function accountStatus() {
  const sequence = ++accountStatusSequence;
  const session = await fetch("/auth/status", {cache:"no-store", credentials:"same-origin"});
  if (!session.ok) { accountGate(); return; }
  const auth = await session.json();
  if (sequence !== accountStatusSequence) return;
  if (!auth.owner || !auth.recent_owner) { accountGate(); return; }
  const response = await fetch("/accounts/status", {cache:"no-store", credentials:"same-origin"});
  if (!response.ok) { accountGate(); return; }
  const status = await response.json();
  if (sequence !== accountStatusSequence) return;
  if (accountState) providers.forEach(provider => {
    if (accountState.accounts[provider].revision !== status.accounts[provider].revision) {
      accountEl(provider).reset();
      accountEl(provider + "-result").textContent = "Die Kontoeinrichtung hat sich geändert. Prüfe sie vor einer neuen Speicherung.";
      if (provider === "carddav") { contactsClear(); accountEl("contacts-result").textContent = "Das Kontaktkonto hat sich geändert. Lade die Adressbücher neu; bisherige Freigaben gelten nicht mehr."; }
      if (provider === "caldav") {
        calendarClear();
        accountEl("calendar-result").textContent = "Das CalDAV-Konto hat sich geändert. Lade die Kalender neu; bisherige Freigaben gelten nicht mehr.";
      }
    }
  });
  accountState = {csrf:auth.csrf, accounts:status.accounts, protocols:status.protocols}; accountReady = true;
  accountEl("forms").hidden = false; accountEl("calendar-access").hidden = false; accountEl("contacts-access").hidden = false; accountEl("renew").hidden = true;
  providers.forEach(provider => {
    const item = status.accounts[provider], badge = accountEl(provider + "-status");
    badge.textContent = item.error ? "Speicher prüfen" : item.configured ? "Eingerichtet" : "Nicht eingerichtet";
    badge.classList.toggle("connected", item.configured);
    const profile = status.protocols?.[provider];
    if (profile) accountEl(provider + "-profile").textContent = (profile.experimental ? "Eigener Anbieter · experimentell: " : "Voreinstellung: ") + (provider === "mail" ? profile.imap_host + " / " + profile.smtp_host : profile.origin);
  });
  accountButtons();
}
const accountErrors = {
  provider_profile_changed_reenter_credentials:"Der Betreiber hat das Serverprofil geändert. Prüfe die angezeigten Server und gib die Zugangsdaten erneut ein.",
  provider_busy_try_again:"Das Konto wird gerade verwendet. Versuche es danach erneut.",
  account_changed_reload_form:"Die Kontoeinrichtung hat sich geändert. Lade die Seite neu.",
  connection_check_failed:"Prüfe Anmeldeadresse, App-Passwort und Erreichbarkeit.",
  invalid_account_input:"Prüfe den Anmeldenamen, die Absenderadresse bei Mail und das App-Passwort ohne Zeilenumbrüche.",
  persistent_storage_confirmation_required:"Bestätige die dauerhafte Speicherung, bevor du speicherst.",
  account_save_unavailable_check_status:"Prüfe zuerst den Status; wiederhole die Speicherung nicht automatisch."
};
async function accountAction(provider, action) {
  if (!accountReady || accountBusy || !accountEl(provider).reportValidity()) return;
  if (action === "save" && !accountEl(provider + "-persist").checked) {
    accountEl(provider + "-result").textContent = accountErrors.persistent_storage_confirmation_required; return;
  }
  accountBusy = true; accountStatusSequence++; accountButtons();
  let payload = null;
  try {
    payload = {provider, username:accountEl(provider + "-user").value, app_password:accountEl(provider + "-password").value, csrf:accountState.csrf};
    if (provider === "mail") payload.sender_email = accountEl("mail-sender").value;
    if (action === "save") Object.assign(payload, {expected_revision:accountState.accounts[provider].revision, persistent_storage_confirmed:true});
    const response = await fetch("/accounts/" + action, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload), credentials:"same-origin", cache:"no-store"});
    const result = await response.json();
    if (response.status === 401) { accountGate(); return; }
    if (!response.ok) { accountEl(provider + "-result").textContent = accountErrors[result.error] || "Anfrage abgelehnt. Prüfe deine Sitzung und Eingabe."; return; }
    if (action === "save") {
      accountEl(provider).reset();
      if (provider === "caldav") calendarClear();
      if (provider === "carddav") contactsClear();
      accountEl(provider + "-result").textContent = "Gespeichert. Die Eingabefelder sind geleert. Prüfe die Verbindung separat.";
      await accountStatus();
    } else accountEl(provider + "-result").textContent = "Anmeldung geprüft. Nichts wurde gesendet, verändert oder gespeichert.";
  } catch (_) { accountEl(provider + "-result").textContent = "Dienst nicht erreichbar. Prüfe den Status; wiederhole eine Speicherung nicht automatisch."; }
  finally {
    if (payload) { payload.username = null; payload.app_password = null; payload.sender_email = null; payload = null; }
    accountBusy = false; accountButtons();
  }
}
const calendarErrors = {
  calendar_account_changed_reload:"Das CalDAV-Konto hat sich geändert. Lade die Kalender neu.",
  calendar_consent_changed_reload:"Die Freigabe hat sich geändert. Lade die Kalender neu.",
  calendar_write_permission_denied:"Der Anbieter meldet keine Schreibberechtigung. Eine Aktivierung ist nicht möglich.",
  calendar_audience_acknowledgement_required:"Bestätige mögliche Sichtbarkeit und Benachrichtigungen für andere Mitglieder.",
  calendar_capability_confirmation_required:"Bestätige, dass dies nur eine technische Kalenderfreigabe ist.",
  provider_busy_try_again:"Das CalDAV-Konto wird gerade verwendet. Versuche es danach erneut."
};
async function calendarRequest(path, payload) {
  const options = {credentials:"same-origin", cache:"no-store"};
  if (payload) Object.assign(options, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({...payload, csrf:accountState.csrf})});
  const response = await fetch("/accounts/calendars" + path, options), result = await response.json();
  if (response.status === 401) { accountGate(); return null; }
  if (!response.ok) {
    if (response.status === 409) calendarClear();
    accountEl("calendar-result").textContent = calendarErrors[result.error] || "Anfrage abgelehnt. Prüfe Sitzung und Auswahl; lade den Status neu.";
    return null;
  }
  return result;
}
function calendarPayload(row) {
  return {calendar_id:row.id, expected_revision:calendarState.account_revision, expected_generation:row.generation};
}
async function calendarLoad() {
  const result = await calendarRequest("", null);
  if (!result) return;
  calendarClear(); calendarState = result;
  for (const row of result.items) {
    const item = document.createElement("div"); item.className = "calendar-row";
    const info = document.createElement("div"), name = document.createElement("strong"), id = document.createElement("span"), state = document.createElement("span");
    name.textContent = row.name; id.textContent = "Kennung: " + row.id; id.className = "help calendar-id";
    state.textContent = row.write_enabled ? "Schreibzugriff aktiv" : "Schreibzugriff aus"; state.className = "badge";
    info.append(name, id, state); item.append(info);
    const actions = document.createElement("div"); actions.className = "actions";
    if (row.available_for_selection) {
      const inspect = document.createElement("button"); inspect.type = "button"; inspect.className = "secondary";
      inspect.textContent = row.write_enabled ? "Freigabe prüfen" : "Diesen Kalender auswählen";
      inspect.addEventListener("click", () => calendarRun(async () => {
        const request = calendarPayload(row), review = await calendarRequest("/inspect", request);
        if (!review) return;
        calendarCancel(); calendarReview = {...review, request};
        accountEl("calendar-review-name").textContent = review.calendar_name;
        accountEl("calendar-review-id").textContent = "Kennung: " + row.id;
        accountEl("calendar-audience").textContent = review.calendar_audience === "private_verified" ? "Die Anbieter-Metadaten bestätigen Zugriff nur für den Eigentümer." : review.calendar_audience === "shared_or_public" ? "Der Anbieter meldet eine Freigabe für andere." : "Die Sichtbarkeit konnte anhand der Anbieter-Metadaten nicht bestätigt werden.";
        accountEl("calendar-permission").textContent = review.write_permission === "available" ? "Der Anbieter meldet Schreibrechte. Einzelne Aktionen können eingeschränkt sein." : review.write_permission === "denied" ? calendarErrors.calendar_write_permission_denied : "Schreibrechte sind unbekannt. Der Anbieter kann eine spätere Änderung ablehnen.";
        accountEl("calendar-warning").textContent = review.audience_warning;
        accountEl("calendar-warning").hidden = !review.requires_audience_acknowledgement;
        accountEl("calendar-audience-label").hidden = !review.requires_audience_acknowledgement;
        accountEl("calendar-review").hidden = false;
      })); actions.append(inspect);
    }
    if (row.write_enabled) {
      const revoke = document.createElement("button"); revoke.type = "button"; revoke.className = "secondary"; revoke.textContent = "Schreibzugriff widerrufen";
      revoke.addEventListener("click", () => calendarRun(async () => {
        const result = await calendarRequest("/revoke", calendarPayload(row));
        if (result) { await calendarLoad(); accountEl("calendar-result").textContent = "Widerrufen. Alte Vorschauen sind ungültig. Bereits ausgeführte Termine bleiben bestehen."; }
      })); actions.append(revoke);
    }
    item.append(actions); accountEl("calendar-list").append(item);
  }
  accountEl("calendar-result").textContent = result.items.length ? "Wähle selbst einen Kalender. Die Kennung unterscheidet auch Kalender mit gleichem Namen." : "Keine Kalender gefunden.";
}
async function calendarRun(action) {
  if (!accountReady || accountBusy) return;
  accountBusy = true; accountStatusSequence++; accountButtons();
  try { await action(); }
  catch (_) { accountEl("calendar-result").textContent = "Dienst nicht erreichbar. Lade den Status neu; eine Freigabe wird nicht automatisch wiederholt."; }
  finally { accountBusy = false; accountButtons(); }
}
function contactsCancel() {
  contactsReview = null;
  accountEl("contacts-review").reset(); accountEl("contacts-review").hidden = true;
  accountEl("contacts-review-name").textContent = ""; accountEl("contacts-review-id").textContent = "";
}
function contactsClear() { contactsState = null; contactsCancel(); accountEl("contacts-list").replaceChildren(); }
function contactsPayload(row) { return {addressbook_id:row.id, expected_revision:contactsState.account_revision, expected_generation:row.generation}; }
async function contactsRequest(path, payload) {
  const options = {credentials:"same-origin", cache:"no-store"};
  if (payload) Object.assign(options, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({...payload, csrf:accountState.csrf})});
  const response = await fetch("/accounts/contacts" + path, options), result = await response.json();
  if (response.status === 401) { accountGate(); return null; }
  if (!response.ok) {
    if (response.status === 409) contactsClear();
    accountEl("contacts-result").textContent = "Anfrage abgelehnt. Prüfe Sitzung und Auswahl; lade die Adressbücher neu."; return null;
  }
  return result;
}
async function contactsLoad() {
  const result = await contactsRequest("", null); if (!result) return;
  contactsClear(); contactsState = result;
  for (const row of result.items) {
    const item = document.createElement("div"); item.className = "calendar-row";
    const info = document.createElement("div"), name = document.createElement("strong"), id = document.createElement("span"), state = document.createElement("span");
    name.textContent = row.name; id.textContent = "Kennung: " + row.id; id.className = "help calendar-id";
    state.textContent = row.read_enabled ? "Lesezugriff aktiv" : "Lesezugriff aus"; state.className = "badge"; info.append(name, id, state); item.append(info);
    const actions = document.createElement("div"); actions.className = "actions";
    if (row.available_for_selection) {
      const select = document.createElement("button"); select.type = "button"; select.className = "secondary"; select.textContent = "Dieses Adressbuch auswählen";
      select.addEventListener("click", () => {
        if (!accountReady || accountBusy) return;
        contactsCancel(); contactsReview = contactsPayload(row);
        accountEl("contacts-review-name").textContent = row.name; accountEl("contacts-review-id").textContent = "Kennung: " + row.id;
        accountEl("contacts-review").hidden = false; accountButtons();
      }); actions.append(select);
    }
    if (row.read_enabled) {
      const revoke = document.createElement("button"); revoke.type = "button"; revoke.className = "secondary"; revoke.textContent = "Lesezugriff widerrufen";
      revoke.addEventListener("click", () => contactsRun(async () => {
        const result = await contactsRequest("/revoke", contactsPayload(row));
        if (result) { await contactsLoad(); accountEl("contacts-result").textContent = "Widerrufen. Bisherige Kontaktverweise sind ungültig."; }
      })); actions.append(revoke);
    }
    item.append(actions); accountEl("contacts-list").append(item);
  }
  accountEl("contacts-result").textContent = result.items.length ? "Wähle selbst ein Adressbuch für den Lesezugriff." : "Keine Adressbücher gefunden.";
}
async function contactsRun(action) {
  if (!accountReady || accountBusy) return;
  accountBusy = true; accountStatusSequence++; accountButtons();
  try { await action(); }
  catch (_) { accountEl("contacts-result").textContent = "Dienst nicht erreichbar. Prüfe den Status; die Freigabe wird nicht automatisch wiederholt."; }
  finally { accountBusy = false; accountButtons(); }
}
providers.forEach(provider => {
  accountEl(provider).addEventListener("submit", event => event.preventDefault());
  ["check", "save"].forEach(action => accountEl(provider + "-" + action).addEventListener("click", () => accountAction(provider, action)));
});
accountEl("calendar-review").addEventListener("submit", event => event.preventDefault());
accountEl("calendar-load").addEventListener("click", () => calendarRun(calendarLoad));
accountEl("calendar-cancel").addEventListener("click", () => { calendarCancel(); accountButtons(); });
accountEl("calendar-save").addEventListener("click", () => calendarRun(async () => {
  if (!calendarReview) return;
  const capability = accountEl("calendar-capability-ack").checked, audience = accountEl("calendar-audience-ack").checked;
  if (!capability || calendarReview.requires_audience_acknowledgement && !audience) {
    accountEl("calendar-result").textContent = !capability ? calendarErrors.calendar_capability_confirmation_required : calendarErrors.calendar_audience_acknowledgement_required; return;
  }
  const result = await calendarRequest("/save", {...calendarReview.request, audience_acknowledged:audience, capability_only_acknowledged:capability});
  if (result) { await calendarLoad(); accountEl("calendar-result").textContent = "Schreibzugriff für genau diesen Kalender aktiviert. Es wurde kein Termin angelegt oder verändert."; }
}));
accountEl("contacts-review").addEventListener("submit", event => event.preventDefault());
accountEl("contacts-load").addEventListener("click", () => contactsRun(contactsLoad));
accountEl("contacts-cancel").addEventListener("click", () => { contactsCancel(); accountButtons(); });
accountEl("contacts-save").addEventListener("click", () => contactsRun(async () => {
  if (!contactsReview) return;
  if (!accountEl("contacts-read-ack").checked) { accountEl("contacts-result").textContent = "Bestätige den Lesezugriff auf genau dieses Adressbuch."; return; }
  const result = await contactsRequest("/save", {...contactsReview, read_access_acknowledged:true});
  if (result) { await contactsLoad(); accountEl("contacts-result").textContent = "Lesezugriff für genau dieses Adressbuch aktiviert. Kontakte wurden nicht verändert. Die App braucht zusätzlich den Scope contacts:read."; }
}));
accountStatus().then(() => { if (accountReady) accountNotice("Mit Passkey bestätigt. Konten selbst einrichten oder unten Kalender freigeben."); }).catch(accountGate);
setInterval(() => { if (!accountBusy) accountStatus().catch(accountGate); }, 15000);
window.addEventListener("pagehide", () => { providers.forEach(provider => accountEl(provider).reset()); calendarClear(); contactsClear(); });
