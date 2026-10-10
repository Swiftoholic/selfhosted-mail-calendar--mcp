// Synthetic DOM and protocol responses only; never a real account/browser session.
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),{webcrypto}=require('crypto');
const html=fs.readFileSync(__dirname+'/../mcp_bridge/static/accounts.html','utf8');
const code=fs.readFileSync(__dirname+'/../mcp_bridge/static/accounts.js','utf8');
const nodes=new Map();let checks=0;
function equal(a,b){assert.equal(a,b);checks++;}function ok(value,why){assert(value,why);checks++;}
class Element {
  constructor(tag,id=''){this.tagName=tag;this.id=id;this.value='';this.checked=false;this.disabled=false;this.hidden=false;this.required=false;this.textContent='';this.children=[];this.listeners={};this.classList={toggle(){}};}
  reset(){for(const child of this.querySelectorAll('input')){child.value='';child.checked=false;}for(const child of this.querySelectorAll('select'))child.value=child.id==='account-type'?'mail':'';}
  replaceChildren(...children){this.children=children;if(this.tagName==='select')this.value=children[0]?.value||'';}
  append(...children){this.children.push(...children);}
  addEventListener(type,fn){this.listeners[type]=fn;}
  querySelectorAll(tag){return this.children.flatMap(child=>[...(child.tagName===tag?[child]:[]),...child.querySelectorAll(tag)]);}
  reportValidity(){return (!this.required || !!this.value) && this.querySelectorAll('input').every(x=>x.reportValidity());}
}
for(const [,tag,before,id,after] of html.matchAll(/<([a-z]+)([^>]*?)\bid="([^"]+)"([^>]*)>/g)){assert(!nodes.has(id));const node=new Element(tag,id);node.required=/\brequired\b/.test(before+after);node.hidden=/\bhidden\b/.test(before+after);nodes.set(id,node);}
nodes.get('wizard').children=['account-type','account-profile','account-label','account-user','account-sender','account-password','account-capabilities','account-persist'].map(id=>nodes.get(id));
nodes.get('calendar-review').children=['calendar-capability-ack','calendar-audience-ack'].map(id=>nodes.get(id));nodes.get('contacts-review').children=[nodes.get('contacts-read-ack')];
const profileChoices=[{id:'gmx-mail',protocol:'mail',name:'GMX',imap_host:'imap.example.test',smtp_host:'smtp.example.test'},{id:'other-mail',protocol:'mail',name:'Synthetic other',imap_host:'other-imap.example.test',smtp_host:'other-smtp.example.test'},{id:'icloud-caldav',protocol:'caldav',name:'iCloud',origin:'https://calendar.example.test/'},{id:'icloud-carddav',protocol:'carddav',name:'iCloud',origin:'https://contacts.example.test/'}];
const row=(id,protocol)=>({id:id.repeat(24),protocol,profile_id:protocol==='mail'?'gmx-mail':protocol==='caldav'?'icloud-caldav':'icloud-carddav',label:'<img src=x onerror=alert(1)>',username:'synthetic-'+id+'@example.invalid',sender_email:protocol==='mail'?'sender-'+id+'@example.invalid':null,revision:(id==='a'?'1':id==='b'?'2':id==='c'?'3':'4').repeat(24),provider:protocol==='mail'?'GMX':'iCloud',capabilities:[],configured:true,connection:{state:'connected',checked_at:1791648000}});
let items=[row('a','mail'),row('b','mail'),row('c','caldav'),row('d','carddav')],ready=true,calendarEnabled=false,contactEnabled=false,delayCheck=false,deferred=null,delaySave=false,saveDeferred=null,saveStarted=null,sequence=0,delayList=false,delayInspect=false,collectionDeferred=null;
const calls=[],events={},proofs=new Map();
function response(value,status=200){return {ok:status===200,status,json:async()=>value};}
function sendCheck(body){const id=(++sequence).toString(16).padStart(24,'0');proofs.set(id,JSON.stringify({...body,csrf:undefined}));return response({connected:true,check_id:id});}
function sendSave(body){const {check_id,persistent_storage_confirmed,...data}=body;
  if(proofs.get(check_id)!==JSON.stringify({...data,csrf:undefined}))return response({error:'connection_check_required_or_changed'},409);
  const existing=items.find(x=>x.id===body.account_id);const result={...(existing||row('e',body.provider)),id:existing?.id||'e'.repeat(24),revision:'9'.repeat(24),label:body.label,username:body.username,sender_email:body.sender_email,profile_id:body.profile_id,capabilities:body.capabilities};
  items=items.filter(x=>x.id!==result.id).concat(result);proofs.delete(check_id);return response({saved:true,account_id:result.id});}
const context=vm.createContext({document:{getElementById(id){assert(nodes.has(id),'missing DOM id: '+id);return nodes.get(id);},createElement(tag){return new Element(tag);}},window:{addEventListener(type,fn){events[type]=fn;}},setInterval(){},TextEncoder,Uint8Array,AbortController,crypto:webcrypto,fetch:async(path,options={})=>{
  const body=options.body?JSON.parse(options.body):null;calls.push({path,body});
  if(path==='/auth/status')return response({owner:ready,recent_owner:ready,csrf:'synthetic-csrf'});
  if(!ready)return response({error:'recent_owner_session_required'},401);
  if(path==='/accounts/status')return response({items:JSON.parse(JSON.stringify(items)),profile_choices:profileChoices,migration_required:false});
  if(path==='/accounts/manage/check'){
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
}});
vm.runInContext(code,context);const tick=()=>new Promise(resolve=>setImmediate(resolve));
const click=id=>nodes.get(id).listeners.click();const type=(id,value)=>{nodes.get(id).value=value;nodes.get(id).listeners.input?.();};
function accountAction(id,index){return nodes.get('account-list').children.find(x=>x.children[0].children[1].textContent.includes('synthetic-'+id+'@')).children[1].children[index].listeners.click();}
function fill(){type('account-label','Synthetic added');type('account-user','new@example.invalid');type('account-sender','sender-new@example.invalid');type('account-password','SYNTHETIC_ONLY_NOT_A_PASSWORD');}
async function newWizard(){await click('account-add');nodes.get('account-profile').value='gmx-mail';await click('wizard-next');fill();}
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
  console.log(JSON.stringify({frontend_checks:checks,failures:0,synthetic_only:true,no_real_provider_calls:true,cancel_back_double_click_and_account_isolation:true}));
}
run().catch(error=>{console.error(error.stack);process.exitCode=1;});
