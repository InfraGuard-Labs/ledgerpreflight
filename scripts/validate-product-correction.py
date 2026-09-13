"""Docker-only process acceptance: independent identities, grouped decisions and complete evidence."""
import pathlib,subprocess,json,zipfile,shutil,hashlib
root=pathlib.Path('/dist');fixture=root/'synthetic/product-acceptance';out=root/'product-validation';out.mkdir(exist_ok=True);results={}
jar=root/'ledger-preflight-0.1.0.jar'
def hashes(directory):
    return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob('*') if p.is_file()}
before=hashes(fixture)
def assess(name,kind='clean',expected=1,extra=(),kit=None,json_output=True):
    base=fixture/kind
    args=['java','-Xmx256m','-jar',str(jar),'assess','--node',str(base/'current-node'),'--upgrade-kit',str(kit or base/'upgrade-kit'),'--host-environment',str(base/'host.json'),'--output',str(out/name),'--non-interactive','--network-mode','all-4.12']
    if kind=='blocked':args+=['--tvu-results',str(base/'tvu.log'),'--tvu-results',str(base/'errors.zip'),'--verifier-classpath',str(base/'classpath.txt')]
    if json_output:args+=['--json']
    proc=subprocess.run([*args,*map(str,extra)],capture_output=True,timeout=60)
    assert proc.returncode==expected,(name,proc.returncode,proc.stderr.decode())
    assert b'\x1b[' not in proc.stdout
    (out/(name+'.stdout')).write_bytes(proc.stdout);(out/(name+'.stderr')).write_bytes(proc.stderr)
    value=json.loads(proc.stdout) if json_output else json.loads((out/name/'report.json').read_text())
    results[name]={'exit':proc.returncode,'status':value['status'],'noCursorControls':True}
    return value,proc.stdout.decode()
def identity(a):
    d=a['evidence']['discovery'];s=a['evidence']['schema-analysis']['safeSettings']
    assert (a['sourceVersion'],a['targetVersion'])==('4.11.6','4.12.11')
    assert (d['sourcePlatform'],d['targetPlatform'],d['confidence'])==('13','140','HIGH')
    assert d['currentCordappJars']==d['targetCordappJars']==2
    assert s['databaseVendor']=='PostgreSQL'
    assert any(j['role']=='TVU' for j in a['evidence']['upgrade-kit'])
for name,kind,code,state,extra in [('environment','environment',1,'WARNING',()),('blocked','blocked',2,'BLOCKED',()),('ready-for-tvu','clean',1,'READY FOR TVU',()),('ready-to-upgrade','clean',0,'READY TO UPGRADE',('--tvu-results',fixture/'clean/tvu.log'))]:
    a,text=assess(name,kind,code,extra,json_output=False);identity(a);assert a['status']==state
    if kind=='blocked':
        tvu=a['evidence']['tvu-summary'];assert (tvu['expected'],tvu['processed'],tvu['succeeded'],tvu['failed'],tvu['detailedRecords'])==(650,650,449,201,201)
        assert list(tvu['rootCauses'].values())==[201]
        for token in ('201 supplied failures match','WHAT HAPPENED','WHY IT MATTERS','WHAT TO DO','NEXT STEP'):assert token in text
        assert text.count('1. CorDapp compatibility')==1 and text.count('2. TVU validation')==1
        assert 'NoSuchMethodError' not in text and 'Ljava/' not in text
        assert any(f['id']=='LP-LEGACY-001' and f['severity']=='BLOCKED' for f in a['findings'])
        html=(out/name/'report.html').read_text();top=html[:html.index('id="technical"')]
        assert '201 supplied failures match' in top and 'NoSuchMethodError' not in top and 'NoSuchMethodError' in html
# Default deep limits are reached with a compressed large entry, without starving identity.
kit=pathlib.Path('/tmp/partial-target');shutil.copytree(fixture/'clean/upgrade-kit',kit)
with zipfile.ZipFile(kit/'renamed-runtime.bin','a',compression=zipfile.ZIP_DEFLATED) as z:
    with z.open('large-synthetic-data','w') as stream:
        for _ in range(33):stream.write(bytes(1024*1024))
a,_=assess('partial-target-default-limits',kit=kit,expected=4);identity(a)
assert a['evidence']['analysis-coverage']['status']=='PARTIAL'
assert not any(f['severity']=='BLOCKED' for f in a['findings'])
a,_=assess('complete-tvu-cannot-override-partial-static',kit=kit,expected=4,extra=['--tvu-results',fixture/'clean/tvu.log'])
assert a['status']=='UNKNOWN' and a['evidence']['tvu-summary']['completeSuccess']
# Matching primary with additional ordered paths; contradictory defaults remain unresolved.
for name,conf,expected in [
 ('matching-multiple','database.schema=Primary\nhibernate.default_schema=Primary\ndataSource.url="jdbc:postgresql://db.example/db?currentSchema=Primary,shared,reporting"',1),
 ('conflicting-primary','database.schema=Primary\ndataSource.url="jdbc:postgresql://db.example/db?currentSchema=Different,shared"',4),
 ('quoted-search-path','database.schema=Primary\nconnectionInitSql="SET search_path TO \\"Primary\\",SHARED"\ndataSource.url="jdbc:postgresql://db.example/db"',1),
 ('unresolved-path','connectionInitSql="SET search_path TO $user,public"\ndataSource.url="jdbc:postgresql://db.example/db"',4)]:
    path=pathlib.Path('/tmp')/(name+'.conf');path.write_text(conf)
    a,_=assess(name,expected=expected,extra=['--node-conf',path])
    cfg=a['evidence']['schema-analysis']['safeSettings']
    if name=='matching-multiple':assert cfg['schemas']==['Primary','shared','reporting'] and cfg['primarySchema']=='Primary'
    if name=='conflicting-primary':assert cfg['effectiveSchema']=='Ambiguous' and not cfg['primarySchema']
    if name=='quoted-search-path':assert cfg['primarySchema']=='Primary' and cfg['additionalSchemas']==['shared']
    if name=='unresolved-path':assert cfg['schemaResolution']=='UNRESOLVED'
# Support bundle contains the new coverage/configuration evidence, no vendor binaries.
a,_=assess('support','blocked',2,['--support-bundle'])
package=out/'support/support.zip'
with zipfile.ZipFile(package) as z:
    assert 'analysis-coverage.json' in z.namelist() and 'schema-analysis.json' in z.namelist()
    for name in z.namelist():
        assert not name.lower().endswith(('.jar','.bin','.jks','.p12','.pfx','.pem','.key'))
        text=z.read(name).decode();assert 'BEGIN PRIVATE KEY' not in text and 'SyntheticPasswordOnly42' not in text
    for line in z.read('checksums.sha256').decode().splitlines():
        sha,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==sha
assert before==hashes(fixture),'Assessment changed input artifacts'
results['input-immutability']={'allFixtureHashesUnchanged':True}
(root/'product-correction-validation.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
