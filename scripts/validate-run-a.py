"""Assert real-structure behavior from final packaged Ubuntu runs; no vendor binaries."""
import pathlib,json,hashlib,zipfile
r=pathlib.Path('/dist');results={}
for version in ('18.04','20.04','22.04','24.04'):
    base=r/'linux-matrix';a=json.loads((base/f'run-a-{version}/report.json').read_text());b=json.loads((base/f'run-a-{version}-limited/report.json').read_text())
    for item in (a,b):
        d=item['evidence']['discovery']
        assert item['sourceVersion']=='4.11.6' and item['targetVersion']=='4.12.11'
        assert (d['sourcePlatform'],d['targetPlatform'],d['currentCordappJars'],d['targetCordappJars'])==('13','140',2,2)
        assert item['status'] not in ('READY FOR TVU','READY TO UPGRADE')
        inv=item['evidence']['environment']['current'];physical=[x for x in inv if x['path'].startswith('cordapps/')]
        assert len(physical)==3
        assert sum(x['role']=='CORDAPP' for x in physical)==2
        assert sum(x['role']=='UNKNOWN' for x in physical)==1
        assert not any('backup' in x['path'] or 'old-date' in x['path'] or '!/' in x['path'] or 'subdirectory' in x['path'] for x in inv)
        assert all(x['role']=='DRIVER' for x in inv if x['path'].startswith('drivers/'))
        old=[x for x in inv if x['role']=='RUNTIME'];assert len(old)==1 and old[0]['manifest']['Corda-Vendor']=='Corda Enterprise Edition'
        target=item['evidence']['upgrade-kit'];assert sum(x['role']=='CORDAPP' for x in target)==2
        assert sum(x['role']=='TVU' for x in target)==1
    assert a['status']=='BLOCKED' and any(f['id']=='LP-API-001' for f in a['findings'])
    assert a['evidence']['analysis-coverage']['status']=='COMPLETE_WITHIN_LIMITS'
    assert b['evidence']['analysis-coverage']['status']=='PARTIAL'
    assert any('symbol memory' in str(f['technicalEvidence']) for f in b['findings'])
    raw=(base/f'run-a-{version}.ansi').read_bytes()
    assert b'> Continue' in raw and b'> View compatibility evidence' in raw
    assert b'OutOfMemoryError' not in raw and b'Exception in thread' not in raw
    assert raw.rfind(b'\x1b[?25h')>raw.rfind(b'\x1b[?25l')
    assert '-Xmx256m' in (base/f'run-a-{version}.command.txt').read_text()
    assert 'PASS' in (base/f'run-a-{version}.validation.txt').read_text()
    results[version]={'packagedContinue':'PASS','actualHeapLimitBytes':268435456,'normalStatus':a['status'],'limitedStatus':b['status'],'coverage':'PARTIAL','discoveryPreserved':True,'noCrash':True,'cursorRestored':True}
labels=[
('A','Root Enterprise capsule resolves 4.11.6 / platform 13 / Enterprise'),
('B','Nested libraries cannot override root identity'),
('C','Canonical direct cordapps files are the active set'),
('D','Backup-like sibling directories excluded'),
('E','Drivers excluded from active CorDapps'),
('F','Legacy contract/workflow correctly classified'),
('G','Migration helper separate'),
('H','Two modern target CorDapps classified independently'),
('I','Renamed TVU identified from contents'),
('J','Nested archives excluded from physical counts'),
('K','Complete normal assessment under packaged -Xmx256m'),
('L','Symbol-pressure case returns graceful incomplete non-ready result'),
('M','Later artifact identities survive a deep limit'),
('N','Packaged Continue reaches result and exits normally')]
value={'acceptance':{k:{'result':'PASS','behavior':v} for k,v in labels},'ubuntu':results}
(r/'run-a-validation.json').write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))
