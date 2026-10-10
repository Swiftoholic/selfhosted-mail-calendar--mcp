// Conservative release guard; inspect the complete proposed diff as well.
const fs=require('fs'),path=require('path'),cp=require('child_process');
const root=path.resolve(__dirname,'..');
function walk(directory){return fs.readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
  if(entry.name==='.git')return [];
  const name=path.join(directory,entry.name);
  if(entry.isSymbolicLink())throw Error('Symlinks are not release files');
  return entry.isDirectory()?walk(name):[path.relative(root,name).split(path.sep).join('/')];
});}
const files=fs.existsSync(path.join(root,'.git'))
  ?cp.execFileSync('git',['-C',root,'ls-files','--cached','--others','--exclude-standard','-z'],{encoding:'utf8'}).split('\0').filter(Boolean):walk(root);
const findings=[];
const rules=[
 ['private_key',/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
 ['github_token',/\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{35,})\b/],
 ['bearer_value',/\bBearer\s+[A-Za-z0-9._~-]{32,}/],
 ['jwt_value',/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/],
 ['ssh_private_material',/\b(?:openssh[-]key[-]v1|PuTTY-User-Key-File-[23]):?/]
];
for(const file of files){
  if(/(?:^|\/)(?:runtime|identity|secrets|tls|certificates|backups|logs)(?:\/|$)|(?:^|\/)(?:\.env(?:\..+)?|id_(?:rsa|ed25519)|known_hosts)$|\.(?:sqlite.*|db|pem|key|p12|pfx|log|har|pcap|zip|tgz)$/i.test(file)&&file!=='.env.example')findings.push({category:'forbidden_artifact_path',path:file});
  const bytes=fs.readFileSync(path.join(root,file));
  if(bytes.includes(0)){findings.push({category:'binary_file',path:file});continue;}
  const value=bytes.toString('utf8');
  if(file.endsWith('.py')&&/^(?:from|import) personal(?:\.|\s)/m.test(value))findings.push({category:'legacy_package_import',path:file});
  for(const [category,rule] of rules)if(rule.test(value))findings.push({category,path:file});
  if(!file.startsWith('mcp_bridge/tests/')&&!file.startsWith('scripts/test_')&&file!=='THIRD_PARTY_NOTICES.txt'){
    if(/(?:app_password|access_token|refresh_token)\s*[:=]\s*["'][A-Za-z0-9_-]{24,}["']/.test(value))findings.push({category:'possible_embedded_credential',path:file});
  }
}
console.log(JSON.stringify({files:files.length,findings,values_printed:false}));
if(findings.length)process.exitCode=1;
