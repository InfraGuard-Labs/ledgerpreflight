import hashlib, json, pathlib, re, sys, tarfile, zipfile, xml.etree.ElementTree as ET
import jsonschema
root=pathlib.Path('/dist')
schema=json.loads(pathlib.Path('/schema/report-schema.json').read_text())
report=json.loads((root/'example-report.json').read_text())
jsonschema.Draft202012Validator(schema).validate(report)
assert report['status']=='BLOCKED'
assert {'LP-API-001','LP-LEGACY-001','LP-TVU-002','LP-DB-001','LP-INTERNAL-001'} <= {f['id'] for f in report['findings']}
tvu=report['evidence']['tvu-summary']
assert (tvu['processed'],tvu['succeeded'],tvu['failed'],tvu['detailedRecords'])==(650,449,201,3)
assert list(tvu['rootCauses'].values())==[3]
html=(root/'example-report.html').read_text()
assert '<script' not in html.lower()
assert 'Content-Security-Policy' in html
assert 'SyntheticPasswordOnly42' not in html
sbom=json.loads((root/'sbom.cdx.json').read_text())
assert sbom['bomFormat']=='CycloneDX' and sbom['specVersion']=='1.5'
assert len(sbom['components'])>=6
for c in sbom['components']:
    assert c['purl'].startswith(('pkg:maven/','pkg:generic/'))
    if c['purl'].startswith('pkg:maven/'): assert len(c['hashes'][0]['content'])==64
count=failures=errors=skipped=0
for p in sorted((root/'test-results').glob('*.xml')):
    s=ET.parse(p).getroot()
    count+=int(s.attrib['tests']);failures+=int(s.attrib['failures']);errors+=int(s.attrib['errors']);skipped+=int(s.attrib['skipped'])
assert count>=76 and failures==0 and errors==0 and skipped==0
for line in (root/'SHA256SUMS').read_text().splitlines():
    sha,name=line.split('  ',1)
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==sha,name
with tarfile.open(root/'ledger-preflight-0.1.0.tar.gz') as t:
    assert any(x.name.endswith('/ledger-preflight') and x.mode & 0o111 for x in t.getmembers())
    assert all(not pathlib.PurePosixPath(x.name).is_absolute() and '..' not in pathlib.PurePosixPath(x.name).parts for x in t.getmembers())
for p in (root/'offline').glob('*/support.zip'):
    with zipfile.ZipFile(p) as z:
        for n in z.namelist():
            assert not n.endswith(('.jks','.pem','.key','.p12','.pfx','.jar'))
            text=z.read(n).decode()
            assert 'SyntheticPasswordOnly42' not in text
            assert 'BEGIN PRIVATE KEY' not in text
        for line in z.read('checksums.sha256').decode().splitlines():
            sha,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==sha
# Repeat comparison ignores creation timestamps only; all actual analysis must agree.
a=root/'offline'/'repeat-a'/'report.json'; b=root/'offline'/'repeat-b'/'report.json'
if a.exists() and b.exists():
    first=json.loads(a.read_text()); second=json.loads(b.read_text())
    first.pop('timestamp',None);second.pop('timestamp',None);assert first==second
summary={'tests':count,'failures':failures,'errors':errors,'skipped':skipped,'reportSchema':'PASS','syntheticReplay':'BLOCKED as expected','checksums':'PASS','sbomComponents':len(sbom['components']),'supportBundle':'PASS','deterministicRepeat':'PASS' if a.exists() and b.exists() else 'NOT_RUN'}
(root/'validation-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
# Clean Ubuntu matrix and Java8 coexistence evidence are separate from analyzer Java.
matrix={}
for version in ('18.04','20.04','22.04','24.04'):
    path=root/'linux-matrix'/('ubuntu-'+version)/'report.json'
    if path.exists():
        host=json.loads(path.read_text())['evidence']['environment']['host']
        assert version in host['executionOs']
        assert host['currentJava']=='NOT_INSTALLED'
        assert host['analyzerJava'].startswith('17.')
        assert host['targetJavaReadiness']=='UNVERIFIED'
        matrix[version]='PASS: no system Java, bundled runtime'
java8=root/'linux-matrix'/'ubuntu-18.04-java8-ready'/'report.json'
if java8.exists():
    record=json.loads(java8.read_text());host=record['evidence']['environment']['host']
    assert host['currentJava'].startswith('1.8.') and host['analyzerJava'].startswith('17.')
    assert host['targetJavaReadiness']=='USER_REPORTED_COMPATIBLE'
    assert record['status']=='READY TO UPGRADE'
    matrix['18.04-java8']='PASS: Java8 unchanged, private Java17'
summary['ubuntuMatrix']=matrix
(root/'validation-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(matrix,indent=2))

assert {'18.04','20.04','22.04','24.04','18.04-java8'} <= set(matrix), 'Complete Ubuntu/Java8 matrix is required'
