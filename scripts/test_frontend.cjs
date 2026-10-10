// Synthetic DOM and protocol responses only; never a real account/browser session.
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),{webcrypto}=require('crypto');
const html=fs.readFileSync(__dirname+'/../mcp_bridge/static/accounts.html','utf8');
const code=fs.readFileSync(__dirname+'/../mcp_bridge/static/accounts.js','utf8');
const loginHtml=fs.readFileSync(__dirname+'/../mcp_bridge/static/login.html','utf8');
const loginCode=fs.readFileSync(__dirname+'/../mcp_bridge/static/login.js','utf8');
const localeCode=fs.readFileSync(__dirname+'/../mcp_bridge/static/i18n.js','utf8');
let checks=0;
function equal(a,b){assert.equal(a,b);checks++;}function ok(value,why){assert(value,why);checks++;}
function deepEqual(a,b){assert.deepEqual(JSON.parse(JSON.stringify(a)),JSON.parse(JSON.stringify(b)));checks++;}
class Element {
  constructor(tag,attrs={}){this.tagName=tag;this.attributes=attrs;this.id=attrs.id||'';this._value=attrs.value||'';this.checked=false;this.disabled='disabled' in attrs;this.hidden='hidden' in attrs;this.required='required' in attrs;this._text='';this.children=[];this.listeners={};this.className=attrs.class||'';this.type=attrs.type||'';this.classList={contains:name=>this.className.split(' ').includes(name)};}
  get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}
  set textContent(value){this._text=String(value);this.children=[];}
  get value(){return this.tagName==='select'?(this._value||this.children[0]?.value||''):this._value;}
  set value(value){this._value=String(value);}
  getAttribute(name){return this.attributes[name]??null;}
  matches(selector){return selector.startsWith('[')?selector.slice(1,-1) in this.attributes:this.tagName===selector;}
  reset(){for(const child of this.querySelectorAll('input')){child.value='';child.checked=false;}for(const child of this.querySelectorAll('select'))child.value=child.children[0]?.value||'';}
  replaceChildren(...children){this._text='';this.children=children;if(this.tagName==='select')this.value=children[0]?.value||'';}
  append(...children){this.children.push(...children);}
  addEventListener(type,fn){this.listeners[type]=fn;}
  querySelectorAll(selector){return this.children.flatMap(child=>[...(child.matches(selector)?[child]:[]),...child.querySelectorAll(selector)]);}
  reportValidity(){return this.disabled || ((!this.required || !!this.value) && this.querySelectorAll('input').every(x=>x.reportValidity()) && this.querySelectorAll('select').every(x=>x.reportValidity()));}
}
function parseHtml(source){
  const root=new Element('document'),nodes=new Map(),stack=[root],voidTags=new Set(['input','meta','link','br']);
  for(const match of source.matchAll(/<(\/?)([a-z][a-z0-9-]*)([^>]*?)>|([^<]+)/gi)){
    if(match[4]){stack.at(-1)._text+=match[4];continue;}
    const [,closing,tag,rawAttrs]=match;
    if(closing){if(stack.at(-1).tagName===tag)stack.pop();continue;}
    const attrs={};for(const [,name,value] of rawAttrs.matchAll(/([a-z][a-z0-9-]*)(?:="([^"]*)")?/gi))attrs[name]=value??'';
    const node=new Element(tag,attrs);stack.at(-1).append(node);
    if(node.id){assert(!nodes.has(node.id),'duplicate DOM id: '+node.id);nodes.set(node.id,node);}
    if(!voidTags.has(tag))stack.push(node);
  }
  const document={documentElement:root.querySelectorAll('html')[0],title:'',getElementById(id){assert(nodes.has(id),'missing DOM id: '+id);return nodes.get(id);},createElement(tag){return new Element(tag);},querySelectorAll(selector){return root.querySelectorAll(selector);}};
  return {document,nodes};
}
function uiContext(source,language='de-DE',saved=null,extra={}){
  const {document,nodes}=parseHtml(source),values=new Map(saved===null?[]:[['mcp-bridge-language',saved]]),writes=[],events={};
  const window={localStorage:{getItem:key=>values.get(key)??null,setItem(key,value){writes.push({key,value});values.set(key,value);}},addEventListener(type,fn){events[type]=fn;},location:{assign(){throw Error('unexpected redirect');}}};
  const context=vm.createContext({document,window,navigator:{language},setInterval(){},TextEncoder,Uint8Array,AbortController,URL,crypto:webcrypto,...extra});
  // Expose dictionaries only inside this synthetic realm for fallback checks.
  vm.runInContext(localeCode.replace('const supported =','globalThis.testDictionaries=dictionaries; const supported ='),context);
  return {context,nodes,document,writes,values,events};
}
const fixture=uiContext(html),{context,nodes,events}=fixture;
const profileChoices=[{id:'gmx-mail',protocol:'mail',name:'GMX',imap_host:'imap.example.test',smtp_host:'smtp.example.test'},{id:'other-mail',protocol:'mail',name:'Synthetic other',imap_host:'other-imap.example.test',smtp_host:'other-smtp.example.test'},{id:'icloud-caldav',protocol:'caldav',name:'iCloud',origin:'https://calendar.example.test/'},{id:'icloud-carddav',protocol:'carddav',name:'iCloud',origin:'https://contacts.example.test/'}];
Object.assign(profileChoices[0],{info_key:'provider.gmx',supported:true,source_urls:['https://hilfe.gmx.net/pop-imap/'],auth_help_url:'https://hilfe.gmx.net/sicherheit/',verification:'documented_not_live_tested'});
profileChoices.push(...['mail','caldav','carddav'].map(protocol=>({id:'manual:'+protocol,protocol,name:'Custom',supported:true,manual:true,info_key:'provider.manual',source_urls:[]})),
  {id:'google-mail',protocol:'mail',name:'Google / Gmail',supported:true,auth_mode:'conditional_app_password',info_key:'provider.google_mail',imap_host:'imap.gmail.com',smtp_host:'smtp.gmail.com'},
  {id:'microsoft-mail',protocol:'mail',name:'Microsoft',supported:false,auth_mode:'oauth_required',info_key:'provider.microsoft_oauth'},
  {id:'google-caldav',protocol:'caldav',name:'Google',supported:false,auth_mode:'oauth_required',info_key:'provider.google_oauth'},
  {id:'posteo-mail',protocol:'mail',name:'Posteo',supported:false,auth_mode:'manual_only',info_key:'provider.posteo_unverified'},
  {id:'bad-note-mail',protocol:'mail',name:'Synthetic missing note',supported:true,info_key:'provider.missing',source_urls:['javascript:alert(1)','http://invalid.example/','https://user:synthetic@docs.example.org/','https://docs.example.org/manual']});
const row=(id,protocol)=>({id:id.repeat(24),protocol,profile_id:protocol==='mail'?'gmx-mail':protocol==='caldav'?'icloud-caldav':'icloud-carddav',label:'<img src=x onerror=alert(1)>',username:'synthetic-'+id+'@example.invalid',sender_email:protocol==='mail'?'sender-'+id+'@example.invalid':null,revision:(id==='a'?'1':id==='b'?'2':id==='c'?'3':'4').repeat(24),provider:protocol==='mail'?'GMX':'iCloud',capabilities:[],configured:true,connection:{state:'connected',checked_at:1791648000}});
let items=[row('a','mail'),row('b','mail'),row('c','caldav'),row('d','carddav')],ready=true,calendarEnabled=false,contactEnabled=false,delayCheck=false,deferred=null,delaySave=false,saveDeferred=null,saveStarted=null,sequence=0,delayList=false,delayInspect=false,collectionDeferred=null;
const calls=[],proofs=new Map();let newAccounts=0,rejectCheck=null;
function response(value,status=200){return {ok:status===200,status,json:async()=>value};}
function sendCheck(body){const id=(++sequence).toString(16).padStart(24,'0');proofs.set(id,JSON.stringify({...body,csrf:undefined}));return response({connected:true,check_id:id});}
function sendSave(body){const {check_id,persistent_storage_confirmed,...data}=body;
  if(proofs.get(check_id)!==JSON.stringify({...data,csrf:undefined}))return response({error:'connection_check_required_or_changed'},409);
  const existing=items.find(x=>x.id===body.account_id);const result={...(existing||row('e',body.provider)),id:existing?.id||String.fromCharCode(101+newAccounts++).repeat(24),revision:'9'.repeat(24),label:body.label,username:body.username,sender_email:body.sender_email,profile_id:body.profile_id,capabilities:body.capabilities};
  if(body.server_config)result.server_config=body.server_config;else delete result.server_config;
  items=items.filter(x=>x.id!==result.id).concat(result);proofs.delete(check_id);return response({saved:true,account_id:result.id});}
context.fetch=async(path,options={})=>{
  const body=options.body?JSON.parse(options.body):null;calls.push({path,body});
  if(path==='/auth/status')return response({owner:ready,recent_owner:ready,csrf:'synthetic-csrf'});
  if(!ready)return response({error:'recent_owner_session_required'},401);
  if(path==='/accounts/status')return response({items:JSON.parse(JSON.stringify(items)),profile_choices:profileChoices,migration_required:false});
  if(path==='/accounts/manage/check'){
    if(rejectCheck)return response({error:rejectCheck},400);
    if(delayCheck)return new Promise((resolve,reject)=>{deferred=()=>resolve(sendCheck(body));options.signal.addEventListener('abort',()=>reject(new Error('synthetic-abort')));});
    return sendCheck(body);
  }
  if(path==='/accounts/manage/save'){
    if(delaySave)return new Promise(resolve=>{saveDeferred=()=>resolve(sendSave(body));saveStarted?.();});return sendSave(body);
  }
  if(path==='/accounts/manage/retest')return response({connected:true});
  if(path==='/accounts/manage/remove'){items=items.filter(row=>row.id!==body.account_id);return response({removed:true,provider_data_changed:false});}
  if(path==='/accounts/calendars/list'){
    const value=response({items:[{id:'f'.repeat(24),name:'<script>untrusted</script>',write_enabled:calendarEnabled,generation:calendarEnabled?'8'.repeat(24):null,available_for_selection:true}],account_revision:'3'.repeat(24)});
    return delayList?new Promise(resolve=>{collectionDeferred=()=>resolve(value);}):value;
  }
  if(path==='/accounts/calendars/inspect'){
    const value=response({calendar_name:'<script>untrusted</script>',calendar_audience:'unknown',requires_audience_acknowledgement:true,write_permission:'unknown',audience_warning:'Synthetic member warning'});
    return delayInspect?new Promise(resolve=>{collectionDeferred=()=>resolve(value);}):value;
  }
  if(path==='/accounts/calendars/save'){calendarEnabled=true;return response({write_enabled:true});}
  if(path==='/accounts/calendars/revoke'){calendarEnabled=false;return response({write_enabled:false});}
  if(path==='/accounts/contacts/list')return response({items:[{id:'f'.repeat(24),name:'<script>untrusted</script>',read_enabled:contactEnabled,generation:contactEnabled?'7'.repeat(24):null,available_for_selection:true}],account_revision:'4'.repeat(24)});
  if(path==='/accounts/contacts/save'){contactEnabled=true;return response({read_enabled:true});}
  if(path==='/accounts/contacts/revoke'){contactEnabled=false;return response({read_enabled:false});}
  throw Error('unexpected synthetic request');
};
vm.runInContext(code,context);const tick=()=>new Promise(resolve=>setImmediate(resolve));
const click=id=>nodes.get(id).listeners.click();const type=(id,value)=>{nodes.get(id).value=value;nodes.get(id).listeners.input?.();};
const change=(id,value)=>{nodes.get(id).value=value;nodes.get(id).listeners.change?.({target:nodes.get(id)});};
const language=value=>change('language',value);
function accountAction(id,index){return nodes.get('account-list').children.find(x=>x.children[0].children[1].textContent.includes('synthetic-'+id+'@')).children[1].children[index].listeners.click();}
function fill(){type('account-label','Synthetic added');type('account-user','new@example.invalid');type('account-sender','sender-new@example.invalid');type('account-password','SYNTHETIC_ONLY_NOT_A_PASSWORD');}
async function newWizard(profile='gmx-mail',protocol='mail'){await click('account-add');if(protocol!=='mail')change('account-type',protocol);change('account-profile',profile);await click('wizard-next');fill();}
async function run(){
  await tick();ok(!code.includes('innerHTML'));ok(!code.includes('localStorage'));ok(!code.includes('console.'));ok(!code.includes('sessionStorage'));
  equal(nodes.get('account-list').children.length,4);equal(nodes.get('account-list').children[0].children[0].children[0].textContent,items[0].label);
  ok(!calls.some(c=>/manage|calendars|contacts/.test(c.path)),'no automatic provider checks or collection discovery');
  await newWizard();equal(nodes.get('account-capabilities').querySelectorAll('input').filter(x=>x.checked).length,0);
  await click('wizard-back');equal(nodes.get('account-password').value,'');equal(nodes.get('wizard-provider').hidden,false);
  await click('wizard-next');fill();await click('wizard-cancel');equal(nodes.get('account-password').value,'');equal(nodes.get('wizard-panel').hidden,true);
  await newWizard();delayCheck=true;const pending=click('wizard-check');await tick();equal(nodes.get('wizard-check').disabled,true);
  await click('wizard-check');equal(calls.filter(x=>x.path==='/accounts/manage/check').length,1);
  await click('wizard-cancel');equal(nodes.get('account-password').value,'');equal(nodes.get('wizard-panel').hidden,true);await pending;deferred();await tick();equal(nodes.get('wizard-panel').hidden,true);delayCheck=false;
  await newWizard();await click('wizard-check');equal(nodes.get('wizard-review').hidden,false);ok(nodes.get('wizard-save').disabled);
  const countBefore=calls.filter(x=>x.path==='/accounts/manage/save').length;await click('wizard-save');equal(calls.filter(x=>x.path==='/accounts/manage/save').length,countBefore);
  nodes.get('account-persist').checked=true;nodes.get('account-persist').listeners.change();delaySave=true;const started=new Promise(resolve=>{saveStarted=resolve;});const saving=click('wizard-save');await started;ok(nodes.get('wizard-cancel').disabled);ok(nodes.get('wizard-back').disabled);
  await click('wizard-save');equal(calls.filter(x=>x.path==='/accounts/manage/save').length,countBefore+1);saveDeferred();await saving;delaySave=false;
  equal(items.length,5);equal(nodes.get('account-password').value,'');equal(nodes.get('wizard-panel').hidden,true);
  const saved=calls.find(x=>x.path==='/accounts/manage/save').body;equal(saved.account_id,null);equal(saved.capabilities.length,0);ok(!('host' in saved));
  await accountAction('a',0);nodes.get('account-profile').value='gmx-mail';await click('wizard-next');equal(nodes.get('account-user').value,'synthetic-a@example.invalid');equal(nodes.get('account-password').value,'');equal(nodes.get('account-password').required,false);
  await click('wizard-check');equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.app_password,null);equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.account_id,'a'.repeat(24));
  await click('wizard-back');equal(nodes.get('account-password').value,'');ok(nodes.get('wizard-save').disabled);await click('wizard-back');type('account-password','SYNTHETIC_CHANGED');nodes.get('account-profile').value='other-mail';nodes.get('account-profile').listeners.change();equal(nodes.get('account-password').value,'');await click('wizard-cancel');
  await newWizard();delayCheck=true;const backPending=click('wizard-check');await tick();await click('wizard-back');equal(nodes.get('wizard-provider').hidden,false);equal(nodes.get('account-password').value,'');await backPending;deferred();await tick();equal(nodes.get('wizard-review').hidden,true);delayCheck=false;await click('wizard-cancel');
  await accountAction('c',2);ok(!calls.some(c=>c.path==='/accounts/calendars/list'));await click('calendar-load');equal(calls.at(-1).body.account_id,'c'.repeat(24));equal(nodes.get('calendar-list').children[0].children[0].children[0].textContent,'<script>untrusted</script>');
  await nodes.get('calendar-list').children[0].children[1].children[0].listeners.click();equal(nodes.get('calendar-audience-label').hidden,false);equal(nodes.get('calendar-capability-ack').checked,false);equal(nodes.get('calendar-audience-ack').checked,false);
  await click('calendar-save');ok(!calendarEnabled);nodes.get('calendar-capability-ack').checked=true;await click('calendar-save');ok(!calendarEnabled);nodes.get('calendar-audience-ack').checked=true;await click('calendar-save');ok(calendarEnabled);
  const calendarSave=calls.find(x=>x.path==='/accounts/calendars/save').body;equal(calendarSave.account_id,'c'.repeat(24));equal(calendarSave.expected_revision,'3'.repeat(24));equal(calendarSave.audience_acknowledged,true);
  await accountAction('d',2);await click('contacts-load');equal(calls.at(-1).body.account_id,'d'.repeat(24));await nodes.get('contacts-list').children[0].children[1].children[0].listeners.click();await click('contacts-save');ok(!contactEnabled);nodes.get('contacts-read-ack').checked=true;await click('contacts-save');ok(contactEnabled);
  equal(calls.find(x=>x.path==='/accounts/contacts/save').body.account_id,'d'.repeat(24));
  await accountAction('b',2);await click('remove-save');equal(items.length,5);nodes.get('remove-confirm').checked=true;await click('remove-save');equal(items.length,4);ok(items.some(x=>x.id==='a'.repeat(24)));equal(calls.find(x=>x.path==='/accounts/manage/remove').body.account_id,'b'.repeat(24));
  await newWizard();fill();await events.keydown({key:'Escape'});equal(nodes.get('wizard-panel').hidden,true);equal(nodes.get('account-password').value,'');
  await accountAction('c',2);delayList=true;const lateList=click('calendar-load');await tick();ready=false;await vm.runInContext('accountStatus()',context);collectionDeferred();await lateList;
  equal(nodes.get('calendar-list').children.length,0);equal(nodes.get('calendar-review').hidden,true);delayList=false;ready=true;await vm.runInContext('accountStatus()',context);
  await accountAction('c',2);await click('calendar-load');delayInspect=true;const lateInspect=nodes.get('calendar-list').children[0].children[1].children[0].listeners.click();await tick();ready=false;await vm.runInContext('accountStatus()',context);collectionDeferred();await lateInspect;
  equal(nodes.get('calendar-review').hidden,true);equal(nodes.get('calendar-list').children.length,0);delayInspect=false;ready=true;await vm.runInContext('accountStatus()',context);
  await newWizard();ready=false;await vm.runInContext('accountStatus()',context);equal(nodes.get('workspace').hidden,true);equal(nodes.get('account-password').value,'');equal(nodes.get('account-list').children.length,0);equal(nodes.get('calendar-review').hidden,true);equal(nodes.get('contacts-review').hidden,true);ok(nodes.get('account-add').disabled);
  ok(!calls.some(x=>/\/mcp\/|events|send|commit/.test(x.path)),'UI performs no provider mutation');
  await runManualAndLocaleFlows();runDictionaryChecks();await runLoginLocaleChecks();
  ok(fixture.writes.every(x=>x.key==='mcp-bridge-language' && ['de','en'].includes(x.value)),'only the locale choice is stored');
  ok(!calls.some(x=>/\/mcp\/|events|send|commit/.test(x.path)),'no provider writes');
  console.log(JSON.stringify({frontend_checks:checks,failures:0,synthetic_only:true,no_real_provider_calls:true,manual_mail_caldav_carddav:true,endpoint_change_password_reentry:true,locale_default_persistence_fallback:true,login_consent_translated:true,cancel_back_double_click_and_account_isolation:true}));
}
async function runManualAndLocaleFlows(){
  ready=true;await vm.runInContext('accountStatus()',context);
  await newWizard('manual:mail');equal(nodes.get('manual-servers').hidden,false);equal(nodes.get('manual-mail').hidden,false);equal(nodes.get('manual-dav').hidden,true);
  type('imap-host','imap.example.org');type('smtp-host','smtp.example.org');change('smtp-port','587');equal(nodes.get('smtp-tls').value,'starttls_required');
  change('smtp-tls','implicit');equal(nodes.get('smtp-port').value,'465');change('smtp-tls','starttls_required');equal(nodes.get('smtp-port').value,'587');
  equal(nodes.get('account-password').value,'');fill();
  const checksBefore=calls.filter(x=>x.path==='/accounts/manage/check').length;
  for(const host of ['localhost','127.0.0.1','[::1]','mail.local','mail.internal','https://imap.example.org','imap.example.org:993']){
    type('imap-host',host);fill();await click('wizard-check');equal(calls.filter(x=>x.path==='/accounts/manage/check').length,checksBefore);ok(nodes.get('wizard-result').textContent.includes('Serverdaten'));
  }
  type('imap-host','IMAP.EXAMPLE.ORG');fill();await click('wizard-check');
  const tested=calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body;
  deepEqual(tested.server_config,{preset:'custom',imap:{host:'imap.example.org',port:993,tls:'implicit'},smtp:{host:'smtp.example.org',port:587,tls:'starttls_required'}});
  equal(tested.capabilities.length,0);equal(nodes.get('wizard-review').hidden,false);ok(nodes.get('review-servers').textContent.includes('STARTTLS'));
  nodes.get('account-persist').checked=true;nodes.get('account-persist').listeners.change();const providerCalls=calls.length;
  language('en');equal(fixture.document.documentElement.lang,'en');equal(fixture.document.title,'Manage accounts · MCP Bridge');
  equal(nodes.get('account-password').value,'SYNTHETIC_ONLY_NOT_A_PASSWORD');equal(nodes.get('account-persist').checked,true);equal(nodes.get('wizard-save').disabled,false);equal(calls.length,providerCalls);
  ok(nodes.get('review-summary').textContent.includes('Allowed permissions'));ok(nodes.get('wizard-result').textContent.includes('Nothing has been saved'));
  ok(nodes.get('account-list').children[0].children[0].children[2].textContent.includes('Last test'));
  await click('wizard-save');equal(nodes.get('account-password').value,'');equal(nodes.get('wizard-panel').hidden,true);equal(fixture.writes.length,1);deepEqual(fixture.writes[0],{key:'mcp-bridge-language',value:'en'});
  const manual=items.find(row=>row.profile_id==='manual:mail');ok(manual);
  // A different object-key order must not force reentry for an unchanged endpoint.
  manual.username='synthetic-m@example.invalid';manual.server_config={smtp:{tls:'starttls_required',port:587,host:'smtp.example.org'},imap:{tls:'implicit',host:'imap.example.org',port:993},preset:'custom'};
  await vm.runInContext('accountStatus()',context);await accountAction('m',0);await click('wizard-next');
  equal(nodes.get('imap-host').value,'imap.example.org');equal(nodes.get('smtp-port').value,'587');equal(nodes.get('account-password').value,'');equal(nodes.get('account-password').required,false);
  await click('wizard-check');equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.app_password,null);
  const originalRevision=manual.revision;await click('wizard-back');type('smtp-host','new-smtp.example.org');equal(nodes.get('account-password').required,true);ok(nodes.get('wizard-save').disabled);
  const beforeChanged=calls.length;await click('wizard-check');equal(calls.length,beforeChanged);
  type('account-password','SYNTHETIC_NEW_ENDPOINT_PASSWORD');await click('wizard-check');
  equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.expected_revision,originalRevision);
  equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.server_config.smtp.host,'new-smtp.example.org');
  type('smtp-host','third-smtp.example.org');equal(nodes.get('account-password').value,'');equal(nodes.get('account-persist').checked,false);ok(nodes.get('wizard-save').disabled);
  const saveCount=calls.filter(x=>x.path==='/accounts/manage/save').length;nodes.get('account-persist').checked=true;await click('wizard-save');equal(calls.filter(x=>x.path==='/accounts/manage/save').length,saveCount);await click('wizard-cancel');
  await newWizard('manual:caldav','caldav');equal(nodes.get('manual-mail').hidden,true);equal(nodes.get('manual-dav').hidden,false);equal(nodes.get('account-sender').required,false);
  const davCount=calls.filter(x=>x.path==='/accounts/manage/check').length;
  for(const url of ['http://dav.example.org/','https://localhost/','https://192.168.1.1/','https://[::1]/','https://dav.example.org:8080/','https://user:synthetic@dav.example.org/','https://dav.example.org/?token=synthetic','https://dav.example.org/#fragment']){
    type('dav-origin',url);fill();await click('wizard-check');equal(calls.filter(x=>x.path==='/accounts/manage/check').length,davCount);ok(nodes.get('wizard-result').textContent.includes('server settings'));
  }
  type('dav-origin','https://DAV.EXAMPLE.ORG:8443/calendar/');fill();await click('wizard-check');
  deepEqual(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.server_config,{preset:'custom',origin:'https://dav.example.org:8443/calendar/',allowed_hosts:['dav.example.org']});
  equal(nodes.get('imap-host').disabled,true);await click('wizard-cancel');
  await newWizard('manual:carddav','carddav');type('dav-origin','https://contacts.example.org/addressbooks/');fill();await click('wizard-check');
  equal(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.profile_id,'manual:carddav');deepEqual(calls.filter(x=>x.path==='/accounts/manage/check').at(-1).body.server_config.allowed_hosts,['contacts.example.org']);await click('wizard-cancel');
  for(const [profile,protocol,fragment] of [['microsoft-mail','mail','Microsoft'],['google-caldav','caldav','Google'],['posteo-mail','mail','Manual']]){
    await click('account-add');if(protocol!=='mail')change('account-type',protocol);change('account-profile',profile);
    ok(nodes.get('wizard-next').disabled);ok(nodes.get('profile-note').textContent.includes(fragment));const before=calls.length;
    await click('wizard-next');equal(nodes.get('wizard-details').hidden,true);await click('wizard-check');await click('wizard-save');equal(calls.length,before);await click('wizard-cancel');
  }
  await newWizard('google-mail');ok(!nodes.get('wizard-check').disabled);ok(nodes.get('password-provider-note').textContent.includes('Eligible Google accounts'));await click('wizard-cancel');
  await newWizard();ok(nodes.get('password-provider-note').textContent.includes('GMX'));ok(nodes.get('password-second-factor').textContent.includes('Keep two-factor'));
  equal(nodes.get('password-provider-sources').children.length,2);equal(nodes.get('profile-verification').textContent,'This template is based on provider documentation. Your account is only verified when you run its connection test.');
  rejectCheck='invalid_manual_server_config';await click('wizard-check');ok(nodes.get('wizard-result').textContent.includes('server settings'));const rejected=calls.length;
  language('de');ok(nodes.get('wizard-result').textContent.includes('Serverdaten'));equal(calls.length,rejected);ok(nodes.get('password-second-factor').textContent.includes('aktiviert'));rejectCheck=null;await click('wizard-cancel');
  await newWizard('bad-note-mail');ok(nodes.get('password-provider-note').textContent.includes('Anmeldebedingungen'));equal(nodes.get('password-provider-sources').children.length,1);equal(nodes.get('password-provider-sources').children[0].href,'https://docs.example.org/manual');await click('wizard-cancel');
  await accountAction('c',2);await click('calendar-load');await nodes.get('calendar-list').children[0].children[1].children[0].listeners.click();
  equal(nodes.get('calendar-audience-ack').checked,false);nodes.get('calendar-capability-ack').checked=true;const beforeLocale=calls.length;language('en');
  equal(nodes.get('calendar-capability-ack').checked,true);equal(nodes.get('calendar-audience-ack').checked,false);ok(nodes.get('calendar-audience').textContent.includes('could not be verified'));ok(nodes.get('calendar-warning').textContent.includes('Other members'));
  equal(calls.length,beforeLocale);await click('calendar-save');equal(calls.length,beforeLocale);await click('calendar-cancel');
  const timestamp=items[0].connection.checked_at;items[0].connection={state:'never_checked',checked_at:null};await vm.runInContext('accountStatus()',context);
  equal(nodes.get('account-list').children[0].children[0].children[2].textContent,'Not tested yet');items[0].connection={state:'connected',checked_at:timestamp};
  await newWizard('manual:mail');type('imap-host','imap.example.org');type('smtp-host','smtp.example.org');fill();await events.pagehide();equal(nodes.get('account-password').value,'');ok(nodes.get('wizard-save').disabled);await click('wizard-cancel');
}
function runDictionaryChecks(){
  const dictionaries=context.testDictionaries;
  deepEqual(Object.keys(dictionaries.de).sort(),Object.keys(dictionaries.en).sort());
  for(const source of [html,loginHtml]){
    const standalone=uiContext(source,'de-AT');equal(standalone.document.documentElement.lang,'de');
    for(const node of standalone.document.querySelectorAll('[data-i18n]'))ok(standalone.context.window.BridgeI18n.has(node.getAttribute('data-i18n')),'translated static key: '+node.getAttribute('data-i18n'));
    for(const lang of ['en','de']){
      standalone.context.window.BridgeI18n.setLanguage(lang);
      for(const node of standalone.document.querySelectorAll('[data-i18n]'))ok(node.textContent.trim().length>0,'nonempty translated text');
    }
    ok(source.indexOf('/static/i18n.js')<source.indexOf(source===html?'/static/accounts.js':'/static/login.js'));
  }
  for(const [browser,saved,expected] of [['en-US',null,'en'],['fr-FR',null,'en'],['de-AT',null,'de'],['en-GB','de','de'],['de-DE','en','en'],['de-DE','xx','de']])equal(uiContext(html,browser,saved).document.documentElement.lang,expected);
  const fallback=uiContext(html,'de-DE');delete fallback.context.testDictionaries.de['accounts.heading'];
  equal(fallback.context.window.BridgeI18n.t('accounts.heading'),'Accounts');equal(fallback.context.window.BridgeI18n.t('missing.key'),fallback.context.window.BridgeI18n.t('error.generic'));
  const writesBefore=fallback.writes.length;fallback.context.window.BridgeI18n.setLanguage('fr');equal(fallback.writes.length,writesBefore);equal(fallback.document.documentElement.lang,'de');
  fallback.context.window.BridgeI18n.setLanguage('en');const nextPage=uiContext(loginHtml,'de-DE',fallback.values.get('mcp-bridge-language'));equal(nextPage.document.documentElement.lang,'en');
  const blockedStorage={getItem(){throw Error('synthetic blocked storage');},setItem(){throw Error('synthetic blocked storage');}};
  const unavailable=uiContext(html,'en-GB',null,{window:{localStorage:blockedStorage}});
  unavailable.context.window.BridgeI18n.setLanguage('de');equal(unavailable.document.documentElement.lang,'de');
  ok(!localeCode.includes('innerHTML'));ok(!localeCode.includes('console.'));ok(!loginCode.includes('innerHTML'));ok(!loginCode.includes('localStorage'));
}
async function runLoginLocaleChecks(){
  const requests=[],redirects=[];
  let auth={configured:true,owner:true,recent_owner:true,pending_scopes:['mail:read','mail:send','calendars:write','contacts:read','offline_access'],pending_consent_id:'synthetic-consent-1',pending_refresh_available:true,csrf:'synthetic-csrf'};
  const ui=uiContext(loginHtml,'en-GB',null,{fetch:async(path,options={})=>{
    requests.push({path,body:options.body?JSON.parse(options.body):null});
    if(path==='/auth/status')return response({...auth});
    if(path==='/auth/grants')return response({connections:[{id:'synthetic-grant-only',created_at:1791648000,last_used_at:1791648300,idle_expires_at:1794240000,absolute_expires_at:1799424000,scope:'mail:read contacts:read offline_access'}]});
    if(path==='/auth/consent')return response({redirect:'https://untrusted.example.invalid/'});
    if(path==='/auth/grants/revoke')return response({revoked:true});
    throw Error('unexpected synthetic login request');
  }});
  ui.context.window.location.assign=url=>redirects.push(url);vm.runInContext(loginCode,ui.context);await tick();
  equal(ui.document.title,'MCP Bridge · Sign in');ok(ui.nodes.get('permissions').textContent.includes('Send mail'));
  equal(ui.nodes.get('persistent').checked,false);ui.nodes.get('persistent').checked=true;const before=requests.length;
  ui.context.window.BridgeI18n.setLanguage('de');
  equal(ui.nodes.get('persistent').checked,true);equal(requests.length,before);ok(ui.nodes.get('permissions').textContent.includes('Mails versenden'));
  ok(ui.nodes.get('connections-list').children[0].children[3].textContent.includes('widerrufen'));ok(ui.nodes.get('connections-list').children[0].children[1].textContent.includes('UTC'));
  equal(ui.nodes.get('connections-list').children[0].children[2].textContent.includes('offline_access'),false);
  auth={...auth,pending_consent_id:'synthetic-consent-2'};await vm.runInContext('status()',ui.context);equal(ui.nodes.get('persistent').checked,false);
  await ui.nodes.get('approve').listeners.click();equal(redirects.length,0);ok(ui.nodes.get('notice').textContent.includes('Anfrage nicht bestätigt'));
  const failedRequests=requests.length;ui.context.window.BridgeI18n.setLanguage('en');ok(ui.nodes.get('notice').textContent.includes('Request not confirmed'));equal(requests.length,failedRequests);
  const consent=requests.find(x=>x.path==='/auth/consent');equal(consent.body.csrf,'synthetic-csrf');equal(consent.body.persistent,false);
  auth={...auth,recent_owner:false};await vm.runInContext('status()',ui.context);equal(ui.nodes.get('approve').disabled,true);equal(ui.nodes.get('connections-list').children.length,0);
  ok(!requests.some(x=>/options|verify|setup\/request/.test(x.path)),'no automatic passkey ceremony');
}
run().catch(error=>{console.error(error.stack);process.exitCode=1;});
