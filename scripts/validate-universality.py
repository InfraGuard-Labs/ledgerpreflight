"""Run only inside Docker: exact Linux installation paths and deterministic non-TTY choices."""
import pathlib,shutil,subprocess,json,os
r=pathlib.Path('/dist');source=r/'synthetic/clean';out=r/'universality';out.mkdir(exist_ok=True);results={}
def assess(name,node,kit=None,expected=1,extra=(),env=None):
    cmd=['java','-jar',str(r/'ledger-preflight-0.1.0.jar'),'assess','--node',str(node),'--upgrade-kit',str(kit or source/'upgrade-kit'),'--output',str(out/name),'--json',*extra]
    p=subprocess.run(cmd,capture_output=True,env=env,timeout=45)
    assert p.returncode==expected,(name,p.returncode,p.stderr.decode())
    a=json.loads(p.stdout);results[name]={'exit':p.returncode,'status':a['status']};return a
for n,path in enumerate(['/usr/local/corda/node','/opt/company/ledger/node','/srv/apps/corda/issuer']):
    shutil.copytree(source/'current-node',path);assess('absolute-path-'+str(n+1),path)
link=pathlib.Path('/srv/linked-node');link.symlink_to('/srv/apps/corda/issuer');assess('symlinked-node',link)
company=pathlib.Path('/tmp/company');company.mkdir();shutil.copytree(source/'current-node',company/'one');shutil.copytree(source/'current-node',company/'two')
a=assess('ambiguous-nodes',company,expected=4);assert any(f['id']=='LP-NODE-001' for f in a['findings'])
node=company/'one'
for vendor in ('oracle','sqlserver','unknown'):
    (node/'node.conf').write_text('database.schema=MixedCase\ndatabase.url="jdbc:'+vendor+':example"\n')
    a=assess('vendor-'+vendor,node);assert not any(f['id']=='LP-DB-001' for f in a['findings'])
(node/'node.conf').write_text('database.schema=${LP_REQUIRED_SCHEMA}\n')
assess('unresolved-schema',node,expected=4)
assess('environment-schema',node,env={**os.environ,'LP_REQUIRED_SCHEMA':'public'})
(node/'schema.conf').write_text('database.schema=public\n')
(node/'node.conf').write_text('include "schema.conf"\n')
assess('relative-include',node)
(node/'other.conf').write_text('myLegalName="O=Other,L=London,C=GB"\n')
assess('ambiguous-config',node,expected=4)
assess('explicit-config',node,extra=['--node-conf',str(node/'node.conf')])
kit=pathlib.Path('/tmp/arbitrary-kit');shutil.copytree(source/'upgrade-kit',kit);(kit/'corda.jar').rename(kit/'unrelated.jar');(kit/'transaction-validator.jar').rename(kit/'utility.jar')
assess('nonstandard-artifact-names','/srv/apps/corda/issuer',kit=kit)
# Mandatory sanitized acceptance gate: real manifest/content structures, no vendor binaries.
acceptance=r/'synthetic/discovery-regression'
a=assess('real-style-acceptance',acceptance/'current-node',kit=acceptance/'upgrade-kit',expected=4,env={**os.environ,'LP_HOST_JAVA_VERSION':'1.8.0_242'})
d=a['evidence']['discovery'];cfg=a['evidence']['schema-analysis']['safeSettings']
assert (a['sourceVersion'],a['targetVersion'])==('4.11.6','4.12.11')
assert (d['sourcePlatform'],d['targetPlatform'])==('13','140')
assert (d['currentCordappJars'],d['targetCordappJars'],d['currentOtherJars'])==(2,2,1)
assert d['confidence']=='HIGH' and cfg['effectiveSchema']=='ExampleMixedCaseIssuer'
assert cfg['businessRole']=='Unknown' and a['evidence']['environment']['nodeName']=='ExampleIssuer'
assert a['evidence']['environment']['host']['currentJava']=='1.8.0_242'
assert any(f['id']=='LP-INPUT-001' for f in a['findings']) # Excluded symlinks still prevent an unsupported readiness claim.
for kind,filename,code in [('runtime','corda.jar','LP-DISCOVERY-006'),('tvu','transaction-validator.jar','LP-DISCOVERY-007')]:
    duplicate=pathlib.Path('/tmp/ambiguous-'+kind);shutil.copytree(source/'upgrade-kit',duplicate)
    shutil.copyfile(duplicate/filename,duplicate/'second.jar')
    a=assess('ambiguous-'+kind,source/'current-node',kit=duplicate,expected=4)
    assert any(f['id']==code for f in a['findings'])
    if kind=='runtime':assert a['targetVersion']=='unknown'
(r/'universality-validation.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
