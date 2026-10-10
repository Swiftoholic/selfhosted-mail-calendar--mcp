const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const html = fs.readFileSync(__dirname + '/../mcp_bridge/static/accounts.html', 'utf8');
const nodes = new Map();
class Element {
  constructor(id='') { this.id=id;this.hidden=false;this.disabled=false;this.checked=false;this.value='';this.textContent='';this.children=[];this.listeners={};this.classList={toggle(){}}; }
  reset() { for(const [id,e] of nodes) if(id.startsWith(this.id+'-') || this.id==='calendar-review' && id.startsWith('calendar-') || this.id==='contacts-review' && id.startsWith('contacts-')) {e.checked=false;e.value='';} }
  replaceChildren(...items){this.children=items;}
  append(...items){this.children.push(...items);}
  addEventListener(type,fn){this.listeners[type]=fn;}
  reportValidity(){return true;}
  querySelectorAll(type){return this.children.flatMap(c=>[...(c.type===type?[c]:[]),...c.querySelectorAll(type)]);}
}
for(const [,id] of html.matchAll(/id="([^"]+)"/g)){assert(!nodes.has(id));nodes.set(id,new Element(id));}
const calls=[];let revision='f'.repeat(24), ready=true, enabled=false, contactsEnabled=false;
const rows=()=>[{id:'a'.repeat(24),name:'<img src=x onerror=alert(1)>',generation:enabled?'c'.repeat(24):null,write_enabled:enabled,available_for_selection:true},{id:'b'.repeat(24),name:'<img src=x onerror=alert(1)>',generation:null,write_enabled:false,available_for_selection:true}];
const context = vm.createContext({document:{getElementById(id){assert(nodes.has(id),'missing DOM id: '+id);return nodes.get(id);},createElement(){return new Element();}},window:{addEventListener(){}},setInterval(){},fetch:async (path,options={})=>{
  const body=options.body?JSON.parse(options.body):null;calls.push({path,body});let value;
  if(path==='/auth/status')value={owner:ready,recent_owner:ready,csrf:'synthetic-csrf'};
  else if(path==='/accounts/status')value={accounts:{mail:{configured:true,revision},caldav:{configured:true,revision},carddav:{configured:true,revision}}};
  else if(path==='/accounts/contacts')value={items:[{id:'e'.repeat(24),name:'<img src=x onerror=alert(1)>',generation:contactsEnabled?'2'.repeat(24):null,read_enabled:contactsEnabled,available_for_selection:true}],account_revision:revision};
  else if(path==='/accounts/contacts/save'){contactsEnabled=true;value={read_enabled:true};}
  else if(path==='/accounts/contacts/revoke'){contactsEnabled=false;value={read_enabled:false};}
  else if(path==='/accounts/calendars')value={items:rows(),account_revision:revision};
  else if(path==='/accounts/calendars/inspect')value={calendar_name:rows()[0].name,calendar_audience:'unknown',requires_audience_acknowledgement:true,write_permission:'unknown',audience_warning:'Synthetic member notification warning'};
  else if(path==='/accounts/calendars/save'){enabled=true;value={write_enabled:true};}
  else if(path==='/accounts/calendars/revoke'){enabled=false;value={write_enabled:false};}
  else throw Error('unexpected request');
  return {ok:true,status:200,json:async()=>value};
}});
const code=fs.readFileSync(__dirname+'/../mcp_bridge/static/accounts.js','utf8');
assert(!code.includes('innerHTML'));assert(!code.includes('localStorage'));assert(!code.includes('console.'));
vm.runInContext(code,context);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function run(){
  await tick();
  assert(!calls.some(c=>c.path.startsWith('/accounts/calendars')),'no automatic calendar selection or request');
  await nodes.get('calendar-load').listeners.click();
  assert.equal(nodes.get('calendar-list').children.length,2);
  const first=nodes.get('calendar-list').children[0];assert.equal(first.children[0].children[0].textContent,rows()[0].name);
  await first.children[1].children[0].listeners.click();
  assert.equal(nodes.get('calendar-review').hidden,false);
  assert.equal(nodes.get('calendar-audience-label').hidden,false);
  assert.equal(nodes.get('calendar-warning').hidden,false);
  assert.equal(nodes.get('calendar-capability-ack').checked,false);
  assert.equal(nodes.get('calendar-audience-ack').checked,false);
  await nodes.get('calendar-save').listeners.click();assert(!calls.some(c=>c.path.endsWith('/save')));
  nodes.get('calendar-capability-ack').checked=true;
  await nodes.get('calendar-save').listeners.click();assert(!calls.some(c=>c.path.endsWith('/save')));
  nodes.get('calendar-audience-ack').checked=true;
  await nodes.get('calendar-save').listeners.click();
  const save=calls.find(c=>c.path==='/accounts/calendars/save');assert.equal(save.body.calendar_id,'a'.repeat(24));assert.equal(save.body.expected_generation,null);assert.equal(save.body.expected_revision,revision);assert.equal(save.body.audience_acknowledged,true);assert.equal(save.body.capability_only_acknowledged,true);
  assert.equal(rows()[1].write_enabled,false);assert.equal(nodes.get('calendar-review').hidden,true);
  const actions=nodes.get('calendar-list').children[0].children[1].children;
  await actions[actions.length-1].listeners.click();assert.equal(enabled,false);
  assert(!calls.some(c=>c.path.startsWith('/accounts/contacts')),'no automatic contacts request');
  await nodes.get('contacts-load').listeners.click();
  assert.equal(nodes.get('contacts-list').children.length,1);
  const contactRow=nodes.get('contacts-list').children[0];
  assert.equal(contactRow.children[0].children[0].textContent,'<img src=x onerror=alert(1)>');
  assert.equal(nodes.get('contacts-review').hidden,true);
  await contactRow.children[1].children[0].listeners.click();
  assert.equal(nodes.get('contacts-read-ack').checked,false);
  await nodes.get('contacts-save').listeners.click();assert(!calls.some(c=>c.path==='/accounts/contacts/save'));
  nodes.get('contacts-read-ack').checked=true;await nodes.get('contacts-save').listeners.click();
  const contactSave=calls.find(c=>c.path==='/accounts/contacts/save');assert.equal(contactSave.body.addressbook_id,'e'.repeat(24));assert.equal(contactSave.body.expected_revision,revision);assert.equal(contactSave.body.expected_generation,null);assert.equal(contactSave.body.read_access_acknowledged,true);
  assert.equal(contactsEnabled,true);assert.equal(nodes.get('contacts-review').hidden,true);assert.equal(nodes.get('contacts-read-ack').checked,false);
  const contactActions=nodes.get('contacts-list').children[0].children[1].children;await contactActions[contactActions.length-1].listeners.click();assert.equal(contactsEnabled,false);
  revision='d'.repeat(24);await vm.runInContext('accountStatus()',context);assert.equal(nodes.get('calendar-list').children.length,0);
  assert.equal(nodes.get('contacts-list').children.length,0);
  ready=false;await vm.runInContext('accountStatus()',context);
  assert.equal(nodes.get('calendar-access').hidden,true);assert.equal(nodes.get('calendar-review').hidden,true);
  assert.equal(nodes.get('calendar-load').disabled,true);assert.equal(nodes.get('calendar-save').disabled,true);
  assert.equal(nodes.get('contacts-access').hidden,true);assert.equal(nodes.get('contacts-load').disabled,true);assert.equal(nodes.get('contacts-review').hidden,true);
  assert(!calls.some(c=>/event|mcp/.test(c.path)));
  console.log(JSON.stringify({frontend_checks:30,failures:0,synthetic_only:true,no_automatic_selection:true,no_real_provider_calls:true}));
}
run().catch(e=>{console.error(e.name+': '+e.message);process.exitCode=1;});
