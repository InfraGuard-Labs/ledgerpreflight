"""Verify generated hierarchy proof and A–U against completed Docker evidence."""
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path('/dist')
VARIANTS = ('blocked-no-tvu', 'blocked-tvu', 'compatible')
VERSIONS = ('18.04', '20.04', '22.04', '24.04')
OWNER = 'org/example/helpers/PublicFacade'
DESC = '(Ljava/lang/Iterable;I)I'
REMOVED_OWNER = 'org/example/runtime/Amounts'
REMOVED_DESC = '(Ljava/lang/Iterable;)Ljava/math/BigDecimal;'
SOURCE = 'cordapps/example-old-contract.jar'
CONTEXTS = {'CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def quiet(text):
    for forbidden in ('Compatibility analysis incomplete', 'PublicFacade', 'SourceHelpers', 'TargetHelpers', 'Ljava/',
                      'CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER', 'LP-API', 'LP-INPUT', 'LP-ANALYSIS',
                      'currentInventory', 'View technical evidence', 'View full technical report', 'OutOfMemoryError', 'Exception in thread', 'C:\\Users'):
        assert forbidden not in text, forbidden


def symbol(analysis, owner, member, descriptor):
    records = [entry for entry in analysis['symbols'] if entry['symbol']['owner'] == owner
               and entry['symbol']['member'] == member and entry['symbol']['descriptor'] == descriptor and entry['symbol']['kind'] == 'METHOD']
    assert len(records) == 1
    return records[0]


def report_proof(assessment, variant):
    evidence = assessment['evidence']
    assert (assessment['sourceVersion'], assessment['targetVersion']) == ('4.11.6', '4.12.11')
    assert assessment['status'] == ('READY FOR TVU' if variant == 'compatible' else 'BLOCKED')
    discovery = evidence['discovery']
    assert (discovery['sourcePlatform'], discovery['targetPlatform']) == ('13', '140')
    assert discovery['currentCordappJars'] == discovery['targetCordappJars'] == 2
    assert evidence['environment']['host']['currentJava'] == '1.8.0_242'
    assert evidence['schema-analysis']['safeSettings']['effectiveSchema'] == ('example_issuer' if variant == 'compatible' else 'ExampleSchema')
    assert evidence['analysis-coverage']['status'] == 'PARTIAL'
    analysis = evidence['required-symbol-resolution']
    assert analysis['complete'] is True
    helper = symbol(analysis, OWNER, 'helper', DESC)
    assert helper['resolution'] == 'COMPATIBLE'
    contexts = {item['context']: item for item in helper['contexts']}
    assert set(contexts) == CONTEXTS
    for context, item in contexts.items():
        proof = item['proof']
        declaring = 'org/example/helpers/SourceHelpers' if context == 'CURRENT_NODE_RUNTIME' else 'org/example/helpers/TargetHelpers'
        assert item['resolution'] == 'COMPATIBLE' and proof['classStatus'] == proof['memberStatus'] == 'found'
        assert proof['declaringClass'] == declaring
        assert proof['declaringArtifacts'] and any(origin.endswith('/' + declaring + '.class') for origin in proof['declaringArtifacts'])
        assert any('/lib/generated-helpers.jar!/' in origin for origin in proof['declaringArtifacts'])
        assert all('companion-tool.jar' not in origin for origin in proof['artifacts'] + proof['declaringArtifacts'])
        if context == 'TARGET_VERIFIER':
            assert any('/tools/external-verifier.jar!/' in origin for origin in proof['declaringArtifacts'])
    assert {source['sourceArtifact'] for source in helper['sources']} == {SOURCE}
    assert len({source['sourceClass'] for source in helper['sources']}) == 3
    removed = symbol(analysis, REMOVED_OWNER, 'total', REMOVED_DESC)
    assert removed['resolution'] == ('COMPATIBLE' if variant == 'compatible' else 'MISSING_METHOD')
    for context in removed['contexts']:
        proof = context['proof']
        assert proof['classStatus'] == 'found'
        assert proof['memberStatus'] == ('found' if variant == 'compatible' or context['context'] == 'CURRENT_NODE_RUNTIME' else 'absent')
    findings = assessment['findings']
    assert not any(f['category'] == 'API_COMPATIBILITY' and ('owner: ' + OWNER in f['technicalEvidence'] or f['severity'] == 'UNKNOWN') for f in findings)
    blocked = [f for f in findings if f['category'] == 'API_COMPATIBILITY' and f['severity'] == 'BLOCKED']
    assert len(blocked) == (0 if variant == 'compatible' else 1)
    for finding in blocked:
        assert finding['affectedArtifact'] == 'current/historical/' + SOURCE
        assert 'sourceScope: active-current-cordapp' in finding['technicalEvidence']
        assert 'sourceArtifact: ' + SOURCE in finding['technicalEvidence']
    tvu = evidence['tvu-summary']
    assert evidence['tvu-evidence-supplied'] is (variant == 'blocked-tvu')
    if variant == 'blocked-tvu':
        assert (tvu['processed'], tvu['succeeded'], tvu['failed'], tvu['detailedRecords']) == (650, 449, 201, 201)
        assert len(tvu['rootCauses']) == 1 and list(tvu['rootCauses'].values()) == [201]
        assert sum(f['id'] == 'LP-TVU-002' for f in findings) == 1
    else:
        assert all(tvu.get(key) is None for key in ('processed', 'succeeded', 'failed')) and tvu['detailedRecords'] == 0
    return helper


def check_bundle(path, variant):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert {'assessment.json', 'required-symbol-resolution.json', 'execution-contexts.json', 'sanitized-node.conf', 'checksums.sha256'} <= set(names)
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
    assert read(directory / 'required-symbol-resolution.json') == assessment['evidence']['required-symbol-resolution']
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
        matched = [name] if name.startswith('[') and name in suites[suite]['cases'] else [value for value in suites[suite]['cases'] if value.startswith(name)]
        assert matched, (suite, name)
        return {'suite': suite, 'cases': matched, 'path': suites[suite]['path']}

    tarball = sha(ROOT / 'ledger-preflight-0.1.0-linux-x86_64.tar.gz')
    matrix = ROOT / 'linux-matrix'
    ubuntu, bundles = {}, []
    for version in VERSIONS:
        for variant in VARIANTS:
            name = 'hierarchy-' + variant + '-' + version
            bundles.append(validate_export(matrix / name, variant))
            raw = (matrix / (name + '.ansi')).read_bytes()
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode()).replace('\r', '')
            quiet(text)
            for expected in ('NODE DISCOVERED', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140', '1.8.0_242', 'PostgreSQL', '2 current', '2 target', 'TVU          Found', 'Technical report exported', 'READY TO SHARE', 'Session complete'):
                assert expected in text, (version, variant, expected)
            assert raw.rfind(b'\x1b[?25h') > raw.rfind(b'\x1b[?25l') >= 0
            if variant == 'compatible':
                assert 'READY FOR TVU' in text and 'View compatibility evidence' not in text
            else:
                assert all(value in text for value in ('NOT READY TO UPGRADE', 'COMPATIBILITY EVIDENCE', 'example-old-contract.jar', 'Target verifier', 'Class found', 'Method found', 'Method missing'))
                assert 'example-new-contract.jar' not in text.split('COMPATIBILITY EVIDENCE', 1)[1].split('> Back', 1)[0]
            if variant == 'blocked-tvu':
                assert all(value in text for value in ('650 processed', '449 passed', '201 failed', '201 supplied failures match', 'TVU EVIDENCE'))
            else:
                assert '201 supplied failures match' not in text and 'View TVU evidence' not in text
            command = (matrix / (name + '.command.txt')).read_text().splitlines()
            assert [value for value in command if value.startswith('-Xmx')] == ['-Xmx256m']
            assert ('--tvu-results' in command) is (variant == 'blocked-tvu')
            assert (matrix / (name + '.exit.txt')).read_text().strip() == ('1' if variant == 'compatible' else '2')
            assert (matrix / (name + '.tarball.sha256')).read_text().split()[0] == tarball
            assert 'PASS' in (matrix / (name + '.validation.txt')).read_text()
        ubuntu[version] = 'PASS'
    assert 'Java8 unchanged' in (matrix / 'ubuntu-18.04-java8.validation.txt').read_text()
    terminal = read(ROOT / 'hierarchy-terminal-validation.json')
    assert len(terminal) == 6
    for variant in VARIANTS:
        name = 'hierarchy-' + variant
        assert terminal[name]['exit'] == (1 if variant == 'compatible' else 2)
        assert terminal[name]['terminalRestored'] and terminal[name]['cursorRestored'] and terminal[name]['heap'] == '-Xmx256m'
        assert terminal[name + '-non-tty']['oneJsonDocument'] and terminal[name + '-non-tty']['noCursorControls']
        bundles.append(validate_export(ROOT / 'hierarchy-artifacts' / variant, variant))
        report_proof(read(ROOT / 'terminal-transcripts' / (name + '-non-tty.json')), variant)
    manifest = read(ROOT / 'screenshots/manifest-hierarchy.json')
    assert len(manifest) == 10
    for item in manifest:
        path = ROOT / 'screenshots' / item['file']
        assert sha(path) == item['sha256'] and path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
        assert 'actual Ubuntu PTY emulator cell buffer' in item['source']
        quiet(path.with_name(path.name + '.txt').read_text())
    unchanged = read(ROOT / 'hierarchy-frozen-ux-proof.json')
    assert unchanged['baselineCommit'] == 'b49faabf9baffc537cb38bff845e1f93dc079a79'
    assert all(unchanged[key] is True for key in ('environmentUnchanged', 'legacySchemaCaseVerified', 'tvuCorrelationUnchanged', 'compatibilityMethodUnchanged', 'tvuMethodUnchanged'))
    integration = 'HierarchyIntegrationTest'
    evidence = {
        'A': [case('JvmHierarchyResolutionTest', 'inheritedStaticMethodPreservesPublicFacadeAndDeclaringOrigin'), case(integration, 'publicFacadeThroughNonPublicGeneratedLayersLinksInTheJvm')],
        'B': [case(integration, 'differentCurrentAndTargetGeneratedHierarchiesResolveExactStaticMethod')],
        'C': [case(integration, '[1] helper-missing')],
        'D': [case(integration, '[2] helper-descriptor')],
        'E': [case('JvmHierarchyResolutionTest', 'constructorsAreNotInherited'), case('RequiredSymbolAnalyzerTest', 'constructorDoesNotResolveFromParent')],
        'F': [case('JvmHierarchyResolutionTest', 'inheritedInterfaceMethodResolvesToItsDeclaration'), case('IndependentHierarchyResolutionTest', 'moreSpecificChildInterfaceWinsOverSuperclassInterfaceDefault')],
        'G': [case('JvmHierarchyResolutionTest', 'conflictingDefaultInterfacesRemainUnknown'), case('IndependentHierarchyResolutionTest', 'defaultConflictAcrossSuperclassAndChildInterfacesCannotBeCompatible')],
        'H': [case(integration, 'defaultBoundedLookupResolvesFacadeAcrossRepeatedArchiveFrontiers')],
        'I': [case(integration, '[1] helper-cycle'), case(integration, '[2] helper-parent-missing'), case('IndependentHierarchyResolutionTest', 'excessiveHierarchyDepthRemainsBoundedUnknown')],
        'J': [case(integration, 'publicFacadeThroughNonPublicGeneratedLayersLinksInTheJvm'), case(integration, 'facadeProofExportRetainsReferencedOwnerAndActualDeclaration')],
        'K': [case(integration, 'noTvuKeepsOnlyConfirmedCompatibilityIssueAndSchemaReview')],
        'L': [case(integration, 'noTvuKeepsOnlyConfirmedCompatibilityIssueAndSchemaReview'), 'four packaged blocked-no-tvu reports'],
        'M': [case(integration, 'all201TvuDetailsStillCorrelateWithoutInheritedHelperNoise'), 'four packaged blocked-tvu reports'],
        'N': [case('ExecutionContextSymbolTest', 'nodeAndVerifierCopiesResolveIndependentlyAndGroupOneRemovedMethod')],
        'O': [case('ExecutionContextLookupTest', 'selectedRuntimeWinsOverGenericSupportingDuplicate')],
        'P': [case('ExecutionContextLookupTest', 'verifierWinsBeforeLegacyShimWhenActualOrderIsKnown')],
        'Q': ['hierarchy-frozen-ux-proof.json'], 'R': ['hierarchy-frozen-ux-proof.json', '12 actual packaged Environment screens'],
        'S': [case(integration, 'facadeProofExportRetainsReferencedOwnerAndActualDeclaration'), '15 actual exported assessments'],
        'T': bundles, 'U': [str(path.relative_to(ROOT)) for path in sorted(matrix.glob('hierarchy-*.command.txt'))],
    }
    assert set(evidence) == set('ABCDEFGHIJKLMNOPQRSTU')
    behavior = dict(zip('ABCDEFGHIJKLMNOPQRSTU', (
        'Public facade inherited static calls link through non-public generated layers in the JVM.',
        'Different current and target ancestor chains resolve the exact required method.',
        'A required inherited method removed from the target remains a confirmed blocker.',
        'A changed inherited JVM descriptor remains a confirmed incompatibility.',
        'Constructors are not inherited from a superclass.',
        'Interface method inheritance resolves to its actual declaring interface.',
        'Conflicting interface defaults across class hierarchy levels remain unresolved.',
        'Targeted lookup completes the required hierarchy despite a partial broad index.',
        'Missing and cyclic required ancestors remain bounded and unresolved.',
        'Referenced facade ownership and actual declaration proof both survive export.',
        'The separate confirmed missing-method blocker survives compatible helper resolution.',
        'No-TVU assessment retains the real API blocker and schema review only.',
        'All 201 supplied TVU failures correlate to the preserved real API blocker.',
        'Current runtime, target node and target verifier resolve independently.',
        'Supporting driver duplicates do not replace the selected runtime definition.',
        'Confirmed verifier-first ordering still proves legacy shim shadowing.',
        'Schema evidence and its wording remain unchanged.',
        'Environment and result actions remain unchanged.',
        'Reports include exact member, context and actual declaring-origin proof.',
        'All 15 new support packages contain sanitized, checksummed hierarchy proof.',
        'All four Ubuntu LTS packaged runs use the bundled JVM with -Xmx256m.',
    )))
    result = {'acceptance': {key: {'result': 'PASS', 'behavior': behavior[key], 'evidence': value} for key, value in evidence.items()},
              'junitTotal': sum(value['tests'] for value in suites.values()), 'testIndex': suites, 'ubuntu': ubuntu,
              'newTerminalAndPipeCases': len(terminal), 'newUbuntuPtyCases': len(VERSIONS) * len(VARIANTS),
              'newSupportPackages': bundles, 'screenshots': manifest, 'tarballSha256': tarball,
              'scope': 'Original synthetic hierarchy fixtures and actual packaged runs; both final manual regressions remain required.'}
    (ROOT / 'hierarchy-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'acceptance': {key: 'PASS' for key in evidence}, 'junitTotal': result['junitTotal'], 'ubuntu': ubuntu,
                      'newSupportPackages': len(bundles), 'screenshots': len(manifest), 'tarballSha256': tarball}, indent=2))


if __name__ == '__main__':
    main()
