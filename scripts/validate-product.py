"""Full release CLI process checks, executed in Docker with networking disabled."""
import pathlib,subprocess,json,hashlib,zipfile,xml.etree.ElementTree as ET
r=pathlib.Path('/dist');out=r/'smoke';out.mkdir(exist_ok=True);jar=r/'ledger-preflight-0.1.0.jar';f=r/'synthetic';results={}
def run(name,args,expected,parse=False):
    p=subprocess.run(['java','-Xmx256m','-jar',str(jar),*map(str,args)],capture_output=True,timeout=45)
    (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
    assert p.returncode==expected,(name,p.returncode,p.stderr.decode(errors='replace'))
    value=json.loads(p.stdout) if parse else None
    results[name]={'exit':p.returncode,'json':parse};return value
run('version',['version'],0)
run('help',['--help'],0)
run('inventory',['inventory','--node',f/'replay/current-node'],0,True)
run('analyze-jar',['analyze-jar',f/'replay/current-node/cordapps/contracts.jar'],0,True)
run('compare-runtime',['compare-runtime','--source',f/'replay/current-node/corda.jar','--target',f/'replay/upgrade-kit/corda.jar'],0,True)
run('tvu-failed',['analyze-tvu',f/'replay/tvu.log',f/'replay/errors.zip'],2,True)
run('tvu-success',['analyze-tvu',f/'clean/tvu.log'],0,True)
run('explain',['explain','LP-API-001'],0)
run('rules',['rules','list'],0,True)
base=['assess','--node',f/'clean/current-node','--upgrade-kit',f/'clean/upgrade-kit','--json']
for name,extra,code,state in [('static',[],1,'READY FOR TVU'),('ready',['--tvu-results',f/'clean/tvu.log'],0,'READY TO UPGRADE')]:
    a=run(name,[*base,'--output',out/name,*extra],code,True);assert a['status']==state
conf=pathlib.Path('/tmp/malformed.conf');conf.write_text('database { broken = [')
a=run('unknown',[*base,'--output',out/'unknown','--node-conf',conf],4,True);assert a['status']=='UNKNOWN'
conf=pathlib.Path('/tmp/mixed.conf');conf.write_text('database.schema="MixedCase"\ndatabase.url="jdbc:postgresql://db/example"')
a=run('schema-blocker',[*base,'--output',out/'schema-blocker','--node-conf',conf,'--tvu-results',f/'clean/tvu.log'],2,True);assert a['status']=='BLOCKED'
conf.write_text('database.schema=public\ndataSource.url="jdbc:postgresql://db/example?currentSchema=public,MixedCase"')
a=run('warning',[*base,'--output',out/'warning','--node-conf',conf],1,True);assert a['status']=='WARNING'
run('refuse-node-output',[*base,'--output',f/'clean/current-node/report'],3)
run('syntax-error',['assess'],2)
run('support-bundle',['support-bundle','--assessment',r/'offline/repeat-a','--output',out/'R3-support.zip'],0)
for package in [out/'R3-support.zip',*list((r/'interactive-artifacts').rglob('*.zip'))]:
    with zipfile.ZipFile(package) as z:
        assert not any(n.lower().endswith(('.jks','.p12','.pfx','.pem','.key')) for n in z.namelist())
        for n in z.namelist():
            text=z.read(n).decode();assert 'SyntheticPasswordOnly42' not in text and 'BEGIN PRIVATE KEY' not in text
        for line in z.read('checksums.sha256').decode().splitlines():
            digest,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==digest
for sha in (r/'interactive-artifacts').rglob('*.sha256'):
    digest,name=sha.read_text().strip().split('  ',1);assert hashlib.sha256(sha.with_name(name).read_bytes()).hexdigest()==digest
results['all-support-archives']={'safe':True,'entryHashes':'PASS','externalHashes':'PASS'}
index=[]
for file in sorted((r/'test-results').glob('*.xml')):
    suite=ET.parse(file).getroot()
    assert int(suite.attrib['failures'])==0 and int(suite.attrib['errors'])==0
    for case in suite.findall('testcase'):index.append(case.attrib['classname']+'.'+case.attrib['name'])
(r/'TEST-INDEX.md').write_text('# Fresh automated test evidence\n\n'+''.join('- PASS '+n+'\n' for n in index))
(r/'cli-smoke-validation.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
