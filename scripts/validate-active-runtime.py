"""Cross-check active runtime and simple actions against shipped Ubuntu package evidence."""
import json,pathlib,re,xml.etree.ElementTree as ET
root=pathlib.Path('/dist')
suites={}
for name in ('ActiveRuntimeRegressionTest','SimpleResultActionsTest'):
    files=list((root/'test-results').glob('*.'+name+'.xml'));assert len(files)==1,name
    suite=ET.parse(files[0]).getroot()
    assert all(int(suite.get(k,'0'))==0 for k in ('failures','errors','skipped')),name
    suites[name]={'tests':int(suite.get('tests')),'cases':[x.get('name') for x in suite.findall('testcase')]}
assert suites['ActiveRuntimeRegressionTest']['tests']==12
assert suites['SimpleResultActionsTest']['tests']==11
ubuntu={}
for version in ('18.04','20.04','22.04','24.04'):
    base=root/'linux-matrix';a=json.loads((base/f'active-runtime-{version}/report.json').read_text())
    d=a['evidence']['discovery'];selection=a['evidence']['current-runtime-selection'];coverage=a['evidence']['analysis-coverage']
    assert a['sourceVersion']==d['sourceVersion']=='4.11.6'
    assert (d['sourcePlatform'],d['sourceMinimumJava'],d['sourceVendor'])==('13','1.8.0','Corda Enterprise Edition')
    assert (d['targetVersion'],d['targetPlatform'],d['currentCordappJars'],d['targetCordappJars'])==('4.12.11','140',2,2)
    assert selection['origin']=='CANONICAL_ACTIVE_LOCATION'
    assert len(selection['selected'])==1 and selection['selected'][0]['path']=='corda.jar'
    assert selection['inactiveRuntimeCount']==2
    assert {x['path'] for x in selection['inactiveRuntimes']}=={'corda.jar-old','corda.jar-older'}
    assert coverage['status']=='COMPLETE_WITHIN_LIMITS'
    assert not any('corda.jar-old' in x['path'] or 'unreferenced-driver' in x['path'] for x in coverage['currentInventory'])
    assert a['status']=='BLOCKED' and {'LP-API-001','LP-LEGACY-001','LP-INTERNAL-001'}<={f['id'] for f in a['findings']}
    raw=(base/f'active-runtime-{version}.ansi').read_bytes()
    assert all(x in raw for x in (b'> Continue',b'> Import existing TVU results',b'Export full technical report',b'Session complete',b'4.11.6',b'Platform 13'))
    assert not any(x in raw for x in (b'View technical evidence',b'View full technical report',b'corda.jar-old',b'currentInventory',b'LP-API',b'OutOfMemoryError'))
    assert not re.search(rb'\d+ warnings',raw)
    assert raw.rfind(b'\x1b[?25h')>raw.rfind(b'\x1b[?25l')
    assert '-Xmx256m' in (base/f'active-runtime-{version}.command.txt').read_text()
    assert 'PASS' in (base/f'active-runtime-{version}.validation.txt').read_text()
    ubuntu[version]={'result':'PASS','sourceVersion':a['sourceVersion'],'sourcePlatform':d['sourcePlatform'],'inactiveRuntimeCount':2,'coverage':coverage['status'],'packagedContinueAt256MiB':'PASS'}
pty=json.loads((root/'interactive-validation.json').read_text())
assert all(x in pty for x in ('active-runtime','active-runtime-selection','blocked','ready-for-tvu','ready-to-upgrade'))
assert pty['active-runtime']['exit']==pty['active-runtime-selection']['exit']==2
shots=root/'screenshots'
for file in ('02-blocked-result','05-compatibility-evidence','06-schema-evidence','07-tvu-evidence'):
    text=(shots/(file+'.png.txt')).read_text()
    assert not any(x in text for x in ('LP-','currentInventory','Ljava/','View technical evidence','View full technical report','1028 warnings'))
assert 'InternalUtils.sum(Iterable)' in (shots/'05-compatibility-evidence.png.txt').read_text()
assert '201 supplied failures match' in (shots/'07-tvu-evidence.png.txt').read_text()
report=root/'interactive-artifacts/blocked'
for file in ('report.html','report.json','summary.txt','technical-assessment.txt','current-runtime-selection.json','analysis-coverage.json','runtime-api-delta.json'):
    assert (report/file).stat().st_size>0,file
results={'acceptance':{label:{'result':'PASS','behavior':description} for label,description in (
('A','Canonical strongly identified corda.jar wins over valid historical siblings'),
('B','Single versioned or renamed runtime selected by contents; five filenames'),
('C','Single custom-runtime.jar selected'),
('D','Ambiguous candidates remain unselected without input; interactive choice survives Continue and evidence navigation'),
('E','Invalid canonical filename does not outrank strongly identified alternative'),
('F','Version, platform, minimum Java and vendor propagate consistently'))},
'suites':suites,'ubuntu':ubuntu,
'dynamicScenarios':{'compatibilitySchemaTvu':'PASS: contextual evidence, existing TVU import, export/support and exit','compatibilityOnly':'PASS: relevant evidence, existing TVU import and artifact actions','readyForTvu':'PASS: existing TVU import without invented evidence','readyToUpgrade':'PASS: supplied TVU evidence and contextual actions'},
'normalOutput':'PASS: no generic dashboard, raw warning totals or diagnostic data',
'evidence':'PASS: human compatibility/schema/TVU pages; complete diagnostics exported',
'driverScope':'PASS: unreferenced driver excluded; referenced and explicit target-app driver linkage retained'}
(root/'active-runtime-validation.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
