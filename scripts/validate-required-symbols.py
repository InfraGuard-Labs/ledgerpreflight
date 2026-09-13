"""Verify A-R from completed tests and actual final standalone-package executions.

Run inside Docker with the completed release directory mounted at /dist. This
validator does not execute the product or replace missing evidence with claims.
"""
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path('/dist')
OWNER = 'org/example/runtime/Amounts'
DESCRIPTOR = '(Ljava/lang/Iterable;)Ljava/math/BigDecimal;'
SOURCE = 'cordapps/example-old-contract.jar'
VERSIONS = ('18.04', '20.04', '22.04', '24.04')


def read(path):
    return json.loads(path.read_text())


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


suites = {}
total = 0
for file in sorted((ROOT / 'test-results').glob('TEST-*.xml')):
    suite = ET.parse(file).getroot()
    assert all(int(suite.get(k, '0')) == 0 for k in ('failures', 'errors', 'skipped')), file.name
    cases = suite.findall('testcase')
    assert len(cases) == int(suite.get('tests')), file.name
    for case in cases:
        assert not any(case.find(k) is not None for k in ('failure', 'error', 'skipped')), case.get('name')
    suites[suite.get('name').split('.')[-1]] = {
        'file': str(file.relative_to(ROOT)), 'tests': len(cases),
        'cases': [case.get('name') for case in cases],
    }
    total += len(cases)
assert total > 320, 'The new full suite must exist, not an earlier release test export'


def case(suite, prefix, minimum=1):
    # Gradle's XML uses JUnit invocation display names for parameterized tests.
    parameters = {
        ('RequiredCompatibilityIntegrationTest', 'exactRuntimeProofHasOneRootAndOnlyHistoricalSource'): [
            '[1] method', '[2] class', '[3] descriptor', '[4] field', '[5] field-descriptor',
        ],
        ('CompatibilityProofUxTest', 'explainsIndependentRuntimeProofWithoutDescriptors'): [
            '[1] found, absent, missing-method, METHOD, Class found · Method missing',
            '[2] absent, absent, missing-class, METHOD, Class missing · Method missing',
            '[3] found, descriptor-mismatch, descriptor-mismatch, METHOD, Class found · Method signature changed',
            '[4] found, absent, missing-field, FIELD, Class found · Field missing',
            '[5] found, descriptor-mismatch, descriptor-mismatch, FIELD, Class found · Field signature changed',
        ],
        ('CompatibilityProofUxTest', 'tvuCorrelationCountsOnlySuppliedMatchingFailureDetails'): [
            '[1] 201, 201 supplied failures match, false',
            '[2] 3, 3 supplied failure details match, true',
        ],
    }.get((suite, prefix))
    if parameters is not None:
        assert set(parameters) <= set(suites[suite]['cases']), (suite, parameters)
        selected = parameters
    else:
        selected = [name for name in suites[suite]['cases'] if name.startswith(prefix)]
    assert len(selected) >= minimum, (suite, prefix, selected)
    return {'suite': suite, 'method': prefix, 'cases': selected, 'evidence': suites[suite]['file']}


def symbol(report, expected):
    analysis = report['evidence']['required-symbol-resolution']
    assert analysis['complete'] is True
    required = [p for p in analysis['symbols'] if p['symbol']['owner'] == OWNER and p['symbol']['kind'] == 'METHOD']
    assert len(required) == 1, required
    proof = required[0]
    assert proof['symbol']['member'] == 'total'
    assert proof['symbol']['descriptor'] == DESCRIPTOR
    assert proof['resolution'] == expected
    assert (proof['current']['classStatus'], proof['current']['memberStatus']) == ('found', 'found')
    assert proof['target']['classStatus'] == 'found'
    assert proof['target']['memberStatus'] == ('absent' if expected == 'MISSING_METHOD' else 'found')
    assert {s['sourceArtifact'] for s in proof['sources']} == {SOURCE}
    assert len({s['sourceClass'] for s in proof['sources']}) == 3
    assert all(s['sourceMethod'] == 'verify()V' and s['referenceType'] == 'INVOKESTATIC' for s in proof['sources'])
    for side in ('current', 'target'):
        assert any('!/lib/required-component.jar' in artifact for artifact in proof[side]['artifacts'])
    assert report['evidence']['analysis-coverage']['status'] == 'PARTIAL'
    return proof


def check_bundle(path):
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        assert len(names) == len(set(names))
        assert {'checksums.sha256', 'assessment.json', 'required-symbol-resolution.json', 'sanitized-node.conf'} <= set(names)
        for name in names:
            assert not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts
            assert '/' not in name and '\\' not in name
            assert not name.lower().endswith(('.key', '.pem', '.jks', '.p12', '.pfx', '.jar', '.class', '.bin'))
            data = bundle.read(name).decode('utf-8')
            assert not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', data)
            assert not any(secret in data for secret in ('SyntheticPasswordOnly42', 'SyntheticSecretOnly42'))
            if name.endswith('.json'):
                json.loads(data)
        assessment = json.loads(bundle.read('assessment.json'))
        symbol(assessment, 'MISSING_METHOD')
        for line in bundle.read('checksums.sha256').decode().splitlines():
            digest, name = line.split('  ', 1)
            assert hashlib.sha256(bundle.read(name)).hexdigest() == digest
    checksum = path.with_name(path.name + '.sha256')
    assert checksum.is_file() and checksum.read_text().split()[0] == sha(path)
    return {'path': str(path.relative_to(ROOT)), 'sha256': sha(path), 'entries': len(names)}


tarball_sha = sha(ROOT / 'ledger-preflight-0.1.0-linux-x86_64.tar.gz')
ubuntu, bundles = {}, []
for version in VERSIONS:
    base = ROOT / 'linux-matrix'
    directory = base / ('required-symbols-' + version)
    report = read(directory / 'report.json')
    proof = symbol(report, 'MISSING_METHOD')
    assert report['status'] == 'BLOCKED'
    assert (report['sourceVersion'], report['targetVersion']) == ('4.11.6', '4.12.11')
    discovery = report['evidence']['discovery']
    assert (discovery['sourcePlatform'], discovery['targetPlatform']) == ('13', '140')
    assert discovery['currentCordappJars'] == discovery['targetCordappJars'] == 2
    assert report['evidence']['tvu-evidence-supplied'] is False
    tvu = report['evidence']['tvu-summary']
    assert all(tvu.get(k) is None for k in ('processed', 'succeeded', 'failed'))
    assert tvu['detailedRecords'] == 0 and not tvu['rootCauses']
    roots = [f for f in report['findings'] if f['category'] == 'API_COMPATIBILITY' and f['severity'] == 'BLOCKED']
    assert len(roots) == 1
    assert roots[0]['affectedArtifact'] == 'current/historical/' + SOURCE
    assert 'owner: ' + OWNER in roots[0]['technicalEvidence']
    assert 'resolution: missing-method' in roots[0]['technicalEvidence']
    assert not any(f['id'] in ('LP-API-003', 'LP-INPUT-001') for f in report['findings'])
    assert not any(f['category'] == 'API_COMPATIBILITY' and (f['affectedArtifact'] == 'assessment' or f['affectedArtifact'].startswith('target/')) for f in report['findings'])
    for name in ('report.html', 'summary.txt', 'technical-assessment.txt', 'analysis-coverage.json', 'required-symbol-resolution.json'):
        assert (directory / name).stat().st_size > 0, name
    assert read(directory / 'required-symbol-resolution.json') == report['evidence']['required-symbol-resolution']
    raw = (base / ('required-symbols-' + version + '.ansi')).read_bytes()
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8')).replace('\r', '')
    for expected in ('NODE DISCOVERED', 'ExampleIssuer', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140', '1.8.0_242', 'PostgreSQL', 'ExampleSchema', '2 current', '2 target', 'TVU          Found', '> Continue', 'CorDapp compatibility', 'NOT READY TO UPGRADE', 'WHAT HAPPENED', 'WHY IT MATTERS', 'WHAT TO DO', 'COMPATIBILITY EVIDENCE', 'Referenced by 3 source classes', 'Current runtime · Corda 4.11.6', 'Class found · Method found', 'Target runtime · Corda 4.12.11', 'Class found · Method missing', 'Technical report exported', 'READY TO SHARE', 'Session complete'):
        assert expected in text, (version, expected)
    for forbidden in ('LP-API', 'LP-INPUT', 'LP-ANALYSIS', 'Ljava/', 'currentInventory', 'retainedSymbols', 'Compatibility analysis incomplete', 'View technical evidence', 'View full technical report', 'View TVU evidence', 'OutOfMemoryError', 'Exception in thread', 'Transactions processed', '650 processed', '201 failed'):
        assert forbidden not in text, (version, forbidden)
    assert not re.search(r'\d+ warnings', text)
    page = text.split('COMPATIBILITY EVIDENCE', 1)[1].split('> Back', 1)[0]
    affected = page.split('Affected CorDapp\n', 1)[1].split('\n\nReferenced API', 1)[0].strip()
    assert affected == 'example-old-contract.jar', affected
    assert page.count('Referenced API') == 1
    assert 'org.example.runtime.Amounts.total(Iterable)' in page
    assert raw.rfind(b'\x1b[?25h') > raw.rfind(b'\x1b[?25l') >= 0
    command = (base / ('required-symbols-' + version + '.command.txt')).read_text().splitlines()
    assert command[0].endswith('/runtime/bin/java') and '-Xmx256m' in command
    assert '--tvu-results' not in command
    assert (base / ('required-symbols-' + version + '.exit.txt')).read_text().strip() == '2'
    assert (base / ('required-symbols-' + version + '.tarball.sha256')).read_text().split()[0] == tarball_sha
    assert 'PASS' in (base / ('required-symbols-' + version + '.validation.txt')).read_text()
    package_bundles = list(directory.glob('*-R3-support-*.zip'))
    assert package_bundles, version
    bundles.extend(check_bundle(path) for path in package_bundles)
    assert 'without system Java' in (base / ('ubuntu-' + version + '.validation.txt')).read_text()
    assert '8 environment/cursor cases passed' in (base / ('discovery-terminal-' + version + '.validation.txt')).read_text()
    ubuntu[version] = {'result': 'PASS', 'report': str((directory / 'report.json').relative_to(ROOT)), 'sourceOnly': SOURCE, 'broadCoverage': 'PARTIAL', 'requiredResolution': proof['resolution'], 'heap': '-Xmx256m', 'exitCode': 2, 'tarballSha256': tarball_sha}

compatible = read(ROOT / 'synthetic/required-symbols/compatible-asserted/report.json')
symbol(compatible, 'COMPATIBLE')
# This exported fixture deliberately retains ExampleSchema for the environment UI;
# the lowercase-schema readiness cases are independently asserted in integration tests.
assert compatible['status'] == 'READY FOR TVU'
assert not any(f['id'] == 'LP-DB-001' for f in compatible['findings'])
assert not any(f['category'] == 'API_COMPATIBILITY' and f['severity'] in ('BLOCKED', 'UNKNOWN') for f in compatible['findings'])
assert 'Java8 unchanged' in (ROOT / 'linux-matrix/ubuntu-18.04-java8.validation.txt').read_text()

terminal_results = read(ROOT / 'interactive-validation.json')
for scenario in ('required-symbols', 'required-symbols-tvu'):
    assert terminal_results[scenario]['exit'] == 2
    assert terminal_results[scenario]['terminalRestored'] and terminal_results[scenario]['cursorRestored']
correlated = read(ROOT / 'interactive-artifacts/required-symbols-tvu/report.json')
symbol(correlated, 'MISSING_METHOD')
tvu = correlated['evidence']['tvu-summary']
assert (tvu['processed'], tvu['succeeded'], tvu['failed'], tvu['detailedRecords']) == (650, 449, 201, 201)
assert len(tvu['rootCauses']) == 1 and list(tvu['rootCauses'].values()) == [201]
assert sum(f['id'] == 'LP-TVU-002' for f in correlated['findings']) == 1
assert sum(f['category'] == 'API_COMPATIBILITY' and f['severity'] == 'BLOCKED' for f in correlated['findings']) == 1
manifest = {item['file']: item for item in read(ROOT / 'screenshots/manifest.json')}
screenshots = []
for filename in ('15-required-symbol-environment.png', '16-required-symbol-result.png', '17-required-symbol-proof.png', '18-required-symbol-tvu.png'):
    image = ROOT / 'screenshots' / filename
    assert sha(image) == manifest[filename]['sha256']
    assert 'actual Ubuntu 22.04 PTY' in manifest[filename]['source']
    content = image.with_name(filename + '.txt').read_text()
    assert not any(noise in content for noise in ('LP-', 'Ljava/', 'currentInventory', 'View technical evidence', 'Compatibility analysis incomplete'))
    if filename.startswith('16-'):
        assert 'CorDapp compatibility' in content and 'View compatibility evidence' in content
        assert 'View TVU evidence' not in content and 'Run TVU safely' in content
    if filename.startswith('17-'):
        assert 'example-old-contract.jar' in content and 'Class found' in content and 'Method found' in content and 'Method missing' in content
        assert 'example-new-contract.jar' not in content and 'assessment\n' not in content
    if filename.startswith('18-'):
        assert all(value in content for value in ('650', '449', '201', '201 supplied failures match'))
    screenshots.append({'path': str(image.relative_to(ROOT)), 'sha256': sha(image)})

required = 'RequiredSymbolAnalyzerTest'
integration = 'RequiredCompatibilityIntegrationTest'
ux = 'CompatibilityProofUxTest'
lookup = 'TargetedRuntimeLookupTest'
acceptance = {}


def verified(label, behavior, *evidence):
    acceptance[label] = {'result': 'PASS', 'behavior': behavior, 'evidence': list(evidence)}


verified('A', 'Confirmed missing method with current exact member and target owner present', case(required, 'missingMethodProvesBothClassesAndCurrentExactMember'), case(integration, 'exactRuntimeProofHasOneRootAndOnlyHistoricalSource', 5), 'linux-matrix/required-symbols-*/report.json')
verified('B', 'Missing class requires complete targeted absence proof', case(required, 'ownerAbsentOnlyAfterCompleteLookupIsConfirmedMissingClass'))
verified('C', 'Descriptor change is distinct from missing member; field descriptors covered too', case(required, 'changedDescriptorIsDistinctFromMissingMethodAndExportsAlternatives'), case(required, 'fieldRemovedAndChangedDescriptorAreDistinct'))
verified('D', 'Current runtime independently proves exact required member', case(required, 'missingMethodProvesBothClassesAndCurrentExactMember'), 'four packaged required-symbol-resolution.json exports')
verified('E', 'Compatible target exact member is confirmed independently', case(required, 'exactMemberPresentInBothRuntimesIsCompatible'), 'synthetic/required-symbols/compatible-asserted/report.json')
verified('F', 'Required classes resolved inside selected nested runtime components', case(lookup, 'nestedComponentsAreSearchedThroughTwoLevels'), 'four packaged current and target component origins')
verified('G', 'Broad PARTIAL does not downgrade complete required lookup or block compatible readiness', case(integration, 'broadPartialCannotDowngradeConfirmedMissingMethod'), case(integration, 'broadPartialDoesNotPreventReadinessWhenRequiredSymbolsResolved'), 'four packaged PARTIAL + MISSING_METHOD reports')
verified('H', 'Independent targeted limit and malformed required class produce UNKNOWN, never removal', case(integration, 'targetedLimitNeverClaimsRemoval'), case(integration, 'malformedRequiredClassNeverClaimsRemoval'))
verified('I', 'Only physical current CorDapp source retained with all caller classes', case(required, 'sourceAttributionIsOnlyCurrentPhysicalCordappAndRetainsEveryCaller'), 'four packaged source provenance arrays and human evidence pages')
verified('J', 'Rebuilt target CorDapps are not falsely identified as affected', case(ux, 'onlyProvenSourceBytecodeCanNameAnAffectedCordapp'), 'four packaged source-only affected-artifact assertions')
verified('K', 'Assessment and runtime grouping labels cannot name an affected CorDapp', case(ux, 'onlyProvenSourceBytecodeCanNameAnAffectedCordapp'), 'four packaged affected CorDapp sections')
verified('L', 'Repeated references produce one root cause with all sites retained', case(required, 'duplicateApiReferencesAcrossMethodsRemainOneRootWithAllSites'), case(required, 'getAndPutSameRemovedFieldAreOneRootWithBothReferenceTypes'), 'four packaged one-root/three-source-class assertions')
verified('M', 'Matching 201 detailed failures correlate once; unsupplied failures are not invented', case(integration, 'repeatedTvuFailuresCorrelateToOneGroupedMissingMethod'), case(ux, 'tvuCorrelationCountsOnlySuppliedMatchingFailureDetails', 2), case(ux, 'differentDescriptorDoesNotBecomeMatchingTvuEvidence'), case(ux, 'absentTvuEvidenceNeverCreatesCountsOrAction'), 'interactive-artifacts/required-symbols-tvu/report.json', 'screenshots/18-required-symbol-tvu.png')
verified('N', 'Environment still shows versions/platforms/Java/database/schema/2 current/2 target/TVU Found', 'four actual packaged environment screens', '32 existing clean Ubuntu environment/cursor scenarios')
verified('O', 'Human compatibility proof shows source, API, independent current/target outcomes without raw noise', case(ux, 'explainsIndependentRuntimeProofWithoutDescriptors', 5), 'four actual packaged compatibility evidence screens')
verified('P', 'Full export preserves exact symbols, descriptors, caller provenance and separate broad coverage', case(ux, 'groupedSourceCountAndExportRetainExactProvenance'), 'four packaged HTML/JSON/text and required-symbol-resolution.json exports')
verified('Q', 'Support ZIPs retain required proof, exclude keys/keystores, pass final scanner and checksums', case('EvidenceTest', 'finalScannerFailsClosedAndProducesNoZip'), case('EvidenceTest', 'bundleRejectsUnapprovedEntry'), case('EvidenceTest', 'structuredSecretValuesRedactedWithoutBreakingJson'), *bundles)
verified('R', 'Actual private runtime runs Environment through Continue/evidence/export/support/exit at default -Xmx256m', *[str(path.relative_to(ROOT)) for path in sorted((ROOT / 'linux-matrix').glob('required-symbols-*.command.txt'))])
assert set(acceptance) == set('ABCDEFGHIJKLMNOPQR')
result = {'acceptance': acceptance, 'junitTotal': total, 'suites': {name: suites[name] for name in (required, lookup, integration, ux)}, 'ubuntu': ubuntu, 'java8Coexistence': 'PASS: existing Java 8 unchanged; private runtime used', 'supportPackages': bundles, 'screenshots': screenshots, 'tarballSha256': tarball_sha, 'scope': 'Synthetic required APIs and actual standalone-package executions; manual real Run A remains required.'}
(ROOT / 'required-symbols-validation.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'acceptance': {key: value['result'] for key, value in acceptance.items()}, 'junitTotal': total, 'ubuntu': {key: value['result'] for key, value in ubuntu.items()}, 'supportPackages': len(bundles), 'tarballSha256': tarball_sha}, indent=2))
