"""Cross-check final class-only verifier, schema and A–V acceptance evidence."""
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path('/dist')
VARIANTS = ('blocked-no-tvu', 'blocked-tvu', 'compatible', 'ready')
VERSIONS = ('18.04', '20.04', '22.04', '24.04')
CONTEXTS = {'CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER'}
SOURCE = 'cordapps/example-old-contract.jar'
STATUS = {'blocked-no-tvu': 'BLOCKED', 'blocked-tvu': 'BLOCKED', 'configured': 'BLOCKED',
          'compatible': 'READY FOR TVU', 'ready': 'READY TO UPGRADE', 'unknown': 'UNKNOWN'}
EXIT = {'blocked-no-tvu': 2, 'blocked-tvu': 2, 'configured': 2, 'compatible': 1, 'ready': 0, 'unknown': 4}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def quiet(text):
    for forbidden in ('Compatibility analysis incomplete', 'OrdinaryType', 'PublicFacade', 'SourceHelpers', 'TargetHelpers',
                      'Ljava/', 'CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER', 'LP-API', 'LP-DB',
                      'LP-INPUT', 'LP-ANALYSIS', 'currentInventory', 'View technical evidence', 'View full technical report',
                      'OutOfMemoryError', 'Exception in thread', 'C:\\Users', 'issues need attention', 'issue needs attention'):
        assert forbidden not in text, forbidden


def symbol(analysis, owner, member, descriptor, kind='METHOD'):
    records = [entry for entry in analysis['symbols'] if entry['symbol']['owner'] == owner
               and entry['symbol']['member'] == member and entry['symbol']['descriptor'] == descriptor
               and entry['symbol']['kind'] == kind]
    assert len(records) == 1, (owner, member, descriptor, len(records))
    return records[0]


def report_proof(assessment, variant):
    evidence = assessment['evidence']
    assert (assessment['sourceVersion'], assessment['targetVersion']) == ('4.11.6', '4.12.11')
    assert assessment['status'] == STATUS[variant], (variant, assessment['status'])
    discovery = evidence['discovery']
    assert (discovery['sourcePlatform'], discovery['targetPlatform']) == ('13', '140')
    assert discovery['currentCordappJars'] == discovery['targetCordappJars'] == 2
    assert evidence['environment']['host']['currentJava'] == '1.8.0_242'
    config = evidence['schema-analysis']['safeSettings']
    assert config['effectiveSchema'] == 'ExampleSchema'
    schema = config['tvuSchemaReadiness']
    assert schema['applicable'] is True and schema['effectiveSchema'] == 'ExampleSchema'
    assert schema['proven'] is (not variant.startswith('blocked-'))
    assert schema['status'] == ('UNPROVEN' if variant == 'blocked-tvu' else 'HANDLED' if variant == 'ready' else 'REQUIRED_UNPROVEN' if variant == 'blocked-no-tvu' else 'CONFIGURATION_PROVEN')
    assert schema['mappedProperty'] == 'hibernate.default_schema'
    assert any('only when TVU uses this selected configuration' in text for text in schema['evidence'])
    assert evidence['analysis-coverage']['status'] == 'PARTIAL'
    analysis = evidence['required-symbol-resolution']
    assert analysis['complete'] is (variant != 'unknown')
    records = [entry for entry in analysis['symbols'] if entry['symbol']['owner'] == 'org/example/runtime/OrdinaryType'
               and entry['symbol']['kind'] == 'CLASS']
    assert len(records) == 1
    ordinary = records[0]
    assert ordinary['resolution'] == ('UNKNOWN' if variant == 'unknown' else 'COMPATIBLE')
    assert {source['sourceArtifact'] for source in ordinary['sources']} == {SOURCE}
    contexts = {item['context']: item for item in ordinary['contexts']}
    assert set(contexts) == CONTEXTS
    for context, item in contexts.items():
        uncertain = variant == 'unknown' and context == 'TARGET_VERIFIER'
        assert item['resolution'] == ('UNKNOWN' if uncertain else 'COMPATIBLE')
        assert item['proof']['classStatus'] == ('unknown' if uncertain else 'found')
        if not uncertain:
            assert item['proof']['memberStatus'] == 'not-applicable'
        assert all('companion-tool.jar' not in path for path in item['proof']['artifacts'])
    if variant != 'unknown':
        assert len(contexts['TARGET_VERIFIER']['proof']['artifacts']) >= 2
    helper = symbol(analysis, 'org/example/helpers/PublicFacade', 'helper', '(Ljava/lang/Iterable;I)I')
    assert helper['resolution'] == 'COMPATIBLE'
    for item in helper['contexts']:
        proof = item['proof']
        declaring = 'org/example/helpers/SourceHelpers' if item['context'] == 'CURRENT_NODE_RUNTIME' else 'org/example/helpers/TargetHelpers'
        assert proof['classStatus'] == proof['memberStatus'] == 'found'
        assert proof['declaringClass'] == declaring
        assert any(path.endswith('/' + declaring + '.class') for path in proof['declaringArtifacts'])
        assert all('companion-tool.jar' not in path for path in proof['declaringArtifacts'])
    blocked = variant.startswith('blocked-') or variant == 'configured'
    removed = symbol(analysis, 'org/example/runtime/Amounts', 'total', '(Ljava/lang/Iterable;)Ljava/math/BigDecimal;')
    assert removed['resolution'] == ('MISSING_METHOD' if blocked else 'COMPATIBLE')
    for item in removed['contexts']:
        assert item['proof']['classStatus'] == 'found'
        assert item['proof']['memberStatus'] == ('absent' if blocked and item['context'] != 'CURRENT_NODE_RUNTIME' else 'found')
    findings = assessment['findings']
    apis = [item for item in findings if item['category'] == 'API_COMPATIBILITY' and item['severity'] == 'BLOCKED']
    assert len(apis) == int(blocked)
    for finding in apis:
        assert finding['affectedArtifact'] == 'current/historical/' + SOURCE
        assert 'sourceScope: active-current-cordapp' in finding['technicalEvidence']
    assert any(item['id'] == 'LP-API-003' for item in findings) is (variant == 'unknown')
    assert sum(item['id'] == 'LP-DB-001' and item['severity'] == 'BLOCKED' for item in findings) == int(variant.startswith('blocked-'))
    assert not any(item['id'] == 'LP-DB-001' and item['severity'] == 'WARNING' for item in findings)
    tvu = evidence['tvu-summary']
    assert evidence['tvu-evidence-supplied'] is (variant in ('blocked-tvu', 'ready'))
    if variant == 'blocked-tvu':
        assert (tvu['processed'], tvu['succeeded'], tvu['failed'], tvu['detailedRecords']) == (650, 449, 201, 201)
        assert len(tvu['rootCauses']) == 1 and list(tvu['rootCauses'].values()) == [201]
    elif variant == 'ready':
        assert (tvu['processed'], tvu['succeeded'], tvu['failed'], tvu['detailedRecords']) == (650, 650, 0, 0)
    else:
        assert all(tvu.get(key) is None for key in ('processed', 'succeeded', 'failed'))
    assert sum(item['id'] == 'LP-TVU-002' for item in findings) == int(variant == 'blocked-tvu')
    return ordinary


def result_text(text, variant):
    quiet(text)
    expected = {'blocked-no-tvu': ['CorDapp compatibility', 'Schema configuration'],
                'blocked-tvu': ['CorDapp compatibility', 'TVU validation', 'Schema configuration'],
                'compatible': [], 'ready': []}[variant]
    if expected:
        assert str(len(expected)) + (' blocker' if len(expected) == 1 else ' blockers') in text
        headings = [(number, title.strip()) for number, title in re.findall(r'^([0-9]+)\. (.+)$', text, re.M)]
        assert headings == [(str(i), title) for i, title in enumerate(expected, 1)], headings
    else:
        assert STATUS[variant] in text
    if variant == 'blocked-tvu':
        assert all(term in text for term in ('650 processed', '449 passed', '201 failed', '201 supplied failures match'))


def check_bundle(path, variant):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert {'assessment.json', 'required-symbol-resolution.json', 'execution-contexts.json', 'schema-analysis.json', 'sanitized-node.conf', 'checksums.sha256'} <= set(names)
        for name in names:
            assert '/' not in name and '\\' not in name and not name.startswith('.')
            assert not name.lower().endswith(('.key', '.pem', '.jks', '.p12', '.pfx', '.jar', '.class', '.bin'))
            text = archive.read(name).decode('utf-8')
            assert not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', text)
            assert not any(secret in text for secret in ('SyntheticPasswordOnly42', 'SyntheticSecretOnly42'))
            if name.endswith('.json'):
                json.loads(text)
        assessment = json.loads(archive.read('assessment.json'))
        report_proof(assessment, variant)
        assert json.loads(archive.read('schema-analysis.json')) == assessment['evidence']['schema-analysis']
        assert json.loads(archive.read('required-symbol-resolution.json')) == assessment['evidence']['required-symbol-resolution']
        for line in archive.read('checksums.sha256').decode().splitlines():
            digest, name = line.split('  ', 1)
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    assert path.with_name(path.name + '.sha256').read_text().split()[0] == sha(path)
    return {'path': str(path.relative_to(ROOT)), 'sha256': sha(path)}


def validate_export(directory, variant):
    assessment = read(directory / 'report.json')
    report_proof(assessment, variant)
    for filename in ('report.html', 'summary.txt', 'technical-assessment.txt', 'required-symbol-resolution.json', 'execution-contexts.json'):
        assert (directory / filename).stat().st_size > 0
    result_text((directory / 'summary.txt').read_text(), variant)
    packages = list(directory.glob('*-R3-support-*.zip'))
    assert len(packages) == 1
    return check_bundle(packages[0], variant)


def main():
    suites = {}
    for path in sorted((ROOT / 'test-results').glob('TEST-*.xml')):
        suite = ET.parse(path).getroot()
        assert all(int(suite.get(key, '0')) == 0 for key in ('failures', 'errors', 'skipped'))
        cases = suite.findall('testcase')
        assert len(cases) == int(suite.get('tests'))
        assert all(not any(case.find(key) is not None for key in ('failure', 'error', 'skipped')) for case in cases)
        suites[suite.get('name').split('.')[-1]] = {'tests': len(cases), 'cases': [case.get('name') for case in cases], 'path': str(path.relative_to(ROOT))}
    assert suites

    def case(suite, name):
        matches = [value for value in suites[suite]['cases'] if value.startswith(name)]
        assert matches, (suite, name)
        return {'suite': suite, 'cases': matches, 'path': suites[suite]['path']}

    tarball = sha(ROOT / 'ledger-preflight-0.1.0-linux-x86_64.tar.gz')
    matrix = ROOT / 'linux-matrix'
    bundles, ubuntu = [], {}
    for version in VERSIONS:
        for variant in VARIANTS:
            name = 'blocker-verifier-' + variant + '-' + version
            bundles.append(validate_export(matrix / name, variant))
            raw = (matrix / (name + '.ansi')).read_bytes()
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode()).replace('\r', '')
            quiet(text)
            assert all(value in text for value in ('NODE DISCOVERED', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140', '1.8.0_242', 'PostgreSQL', '2 current', '2 target', 'TVU          Found', 'Technical report exported', 'READY TO SHARE', 'Session complete'))
            assert raw.rfind(b'\x1b[?25h') > raw.rfind(b'\x1b[?25l') >= 0
            command = (matrix / (name + '.command.txt')).read_text().splitlines()
            assert [value for value in command if value.startswith('-Xmx')] == ['-Xmx256m']
            assert ('--tvu-results' in command) is (variant in ('blocked-tvu', 'ready'))
            assert (matrix / (name + '.exit.txt')).read_text().strip() == str(EXIT[variant])
            assert (matrix / (name + '.tarball.sha256')).read_text().split()[0] == tarball
            assert 'PASS' in (matrix / (name + '.validation.txt')).read_text()
        ubuntu[version] = 'PASS'
    assert 'Java8 unchanged' in (matrix / 'ubuntu-18.04-java8.validation.txt').read_text()
    terminal = read(ROOT / 'blocker-verifier-terminal-validation.json')
    assert len(terminal) == 9
    for variant in VARIANTS:
        name = 'blocker-verifier-' + variant
        assert terminal[name]['exit'] == EXIT[variant]
        assert terminal[name]['terminalRestored'] and terminal[name]['cursorRestored'] and terminal[name]['heap'] == '-Xmx256m'
        assert terminal[name + '-non-tty']['oneJsonDocument'] and terminal[name + '-non-tty']['noCursorControls']
        bundles.append(validate_export(ROOT / 'blocker-verifier-artifacts' / variant, variant))
        report_proof(read(ROOT / 'terminal-transcripts' / (name + '-non-tty.json')), variant)
    report_proof(read(ROOT / 'terminal-transcripts/blocker-verifier-unknown-non-tty.json'), 'unknown')
    assert terminal['blocker-verifier-unknown-non-tty']['exit'] == EXIT['unknown']
    report_proof(read(ROOT / 'synthetic/blocker-verifier/configured-asserted/report.json'), 'configured')
    manifest = read(ROOT / 'screenshots/manifest-blocker-verifier.json')
    assert len(manifest) == 11
    for item in manifest:
        path = ROOT / 'screenshots' / item['file']
        assert sha(path) == item['sha256'] and path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
        assert 'actual Ubuntu PTY emulator cell buffer' in item['source']
        quiet(path.with_name(path.name + '.txt').read_text())
    unchanged = read(ROOT / 'release-ux-review.json')
    assert unchanged['status'] == 'PASS'
    assert all(unchanged[key] is True for key in ('environmentReviewed', 'schemaEvidenceReviewed', 'correlationPreserved', 'importOnlySurface'))
    direct, integration = 'VerifierClassResolutionTest', 'BlockerVerifierIntegrationTest'
    evidence = {
        'A': [case(direct, 'equivalentVerifierCopiesResolveClassPresenceWithoutChoosingMemberWinner'), case(direct, 'classPresenceDoesNotDependOnUnneededParent')],
        'B': [case(direct, 'separateNodeAndBundledVerifierCopiesRemainIndependent')],
        'C': [case(direct, 'completeVerifierAbsenceIsConfirmed'), case(integration, 'genuinelyAbsentVerifierClassRemainsAConfirmedCompatibilityBlocker')],
        'D': [case(integration, 'noTvuRequiresCompatibilityAndUnprovenSchemaResolution')],
        'E': [case(direct, 'resolvedOrdinaryClassDoesNotLeaveGenericIncompleteBesideTrueMissingMethod'), '20 packaged reports with complete required proof'],
        'F': [case(direct, 'malformedRequiredClassRemainsUnknown'), case(integration, 'genuineUnresolvedVerifierClassRemainsVisibleWithoutConfirmedBlockerInflation'), 'terminal-transcripts/blocker-verifier-unknown-non-tty.json'],
        'G': [case('SchemaReadinessTest', 'unresolvedMixedCaseSchemaBlocksStaticAssessment')],
        'H': [case('SchemaReadinessTest', 'explicitQuotedSelectedDatabaseSchemaProvidesOnlyStaticConfigurationProof'), case(integration, 'quotedSelectedSchemaConfigurationClearsOnlySchemaBlocker')],
        'I': [case(integration, 'noTvuRequiresCompatibilityAndUnprovenSchemaResolution'), 'five packaged no-TVU reports'],
        'J': [case(integration, 'suppliedFailedTvuAddsExactlyOneBlockerAndPreservesAll201Matches'), 'five packaged failed-TVU reports'],
        'K': [case('SchemaReadinessTest', 'provenConfigurationClearsSchemaBlockerWithoutClaimingTvuSuccess'), 'five packaged READY FOR TVU reports'],
        'L': [case('SchemaReadinessTest', 'provenConfigurationAndSuccessfulTvuCanReachReadyToUpgrade'), 'five packaged READY TO UPGRADE reports'],
        'M': [case(integration, 'suppliedFailedTvuAddsExactlyOneBlockerAndPreservesAll201Matches')],
        'N': ['release-ux-review.json', '20 actual packaged Environment screens'],
        'O': ['release-ux-review.json', 'screenshots/41-blocker-verifier-static-proof.png'],
        'P': ['release-ux-review.json', 'screenshots/42-blocker-verifier-schema.png'],
        'Q': ['release-ux-review.json', 'screenshots/47-blocker-verifier-tvu-evidence.png'],
        'R': [case(integration, 'technicalReportAndSupportZipCarryResolvedClassAndUnchangedMissingMethodProof'), '20 exported HTML/JSON/text assessments'],
        'S': bundles,
        'T': [str(path.relative_to(ROOT)) for path in sorted(matrix.glob('blocker-verifier-*.command.txt'))],
        'U': ubuntu,
        'V': ['linux-matrix/ubuntu-18.04-java8.validation.txt'],
    }
    assert set(evidence) == set('ABCDEFGHIJKLMNOPQRSTUV')
    behaviors = ('Direct CLASS proof resolves equivalent verifier copies without member/hierarchy requirements.',
                 'Node and verifier class copies resolve independently.', 'Complete verifier absence remains confirmed.',
                 'Exact missing methods remain blockers in both target contexts.', 'Resolved required references do not leave false incomplete findings.',
                 'Genuinely malformed required verifier evidence remains unresolved.', 'Unproven applicable mixed-case schema is a blocker.',
                 'Explicit quoted selected configuration clears only the schema blocker.', 'No-TVU result displays compatibility and unproven schema blockers.',
                 'Failed-TVU result displays exactly three blockers.', 'Complete static proof waits in READY FOR TVU.',
                 'Successful required TVU and static proof permit READY TO UPGRADE.', 'All 201 supplied failures remain correlated to the exact API blocker.',
                 'Environment implementation and actual terminal output are preserved.', 'Compatibility evidence implementation remains unchanged.',
                 'Schema evidence separates static configuration from imported loading proof.', 'TVU evidence implementation and correlation remain unchanged.',
                 'Actual report export carries class/member/context and schema proof.', 'All 20 new support ZIPs are sanitized and checksummed.',
                 'Every packaged Ubuntu process runs the bundled JVM with -Xmx256m.', 'Ubuntu 18.04/20.04/22.04/24.04 packaged workflows pass.',
                 'Ubuntu 18.04 Java 8 remains unchanged alongside the bundled analyzer JVM.')
    result = {'acceptance': {key: {'result': 'PASS', 'behavior': behavior, 'evidence': evidence[key]} for key, behavior in zip('ABCDEFGHIJKLMNOPQRSTUV', behaviors)},
              'junitTotal': sum(value['tests'] for value in suites.values()), 'testIndex': suites, 'ubuntu': ubuntu,
              'newTerminalAndPipeCases': len(terminal), 'newUbuntuPtyCases': len(VERSIONS) * len(VARIANTS),
              'newSupportPackages': bundles, 'screenshots': manifest, 'tarballSha256': tarball,
              'scope': 'Synthetic regression and actual Docker packaged runs; both final manual real-environment regressions remain required.'}
    (ROOT / 'blocker-verifier-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'acceptance': {key: 'PASS' for key in evidence}, 'junitTotal': result['junitTotal'], 'ubuntu': ubuntu,
                      'newSupportPackages': len(bundles), 'screenshots': len(manifest), 'tarballSha256': tarball}, indent=2))


if __name__ == '__main__':
    main()
