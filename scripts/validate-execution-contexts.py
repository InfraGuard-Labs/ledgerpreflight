"""Cross-check A–T against completed Docker tests and final packaged executions.

Run in Docker with the completed release mounted at /dist. This verifies existing
evidence; it neither runs the product nor substitutes assertions for missing runs.
"""
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path('/dist')
VERSIONS = ('18.04', '20.04', '22.04', '24.04')
VARIANTS = ('blocked', 'verifier-only', 'compatible')
OWNER = 'org/example/runtime/Amounts'
DESCRIPTOR = '(Ljava/lang/Iterable;)Ljava/math/BigDecimal;'
SOURCE = 'cordapps/example-old-contract.jar'
CONTEXTS = ('CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER')


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path):
    return str(path.relative_to(ROOT))


def quiet(text):
    for forbidden in ('C:\\Users', 'LP-API', 'LP-INPUT', 'LP-ANALYSIS', 'Ljava/', 'CURRENT_NODE_RUNTIME',
                      'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER', 'currentInventory', 'targetInventory',
                      'View technical evidence', 'View full technical report', 'REQUIRED_OR_UNRESOLVED',
                      'Analyzer:', 'SyntheticPasswordOnly42', 'OutOfMemoryError', 'Exception in thread',
                      'Compatibility analysis incomplete', '650 processed', '201 failed', 'Transactions processed'):
        assert forbidden not in text, forbidden
    assert not re.search(r'\d+ warnings', text)


suites = {}
for path in sorted((ROOT / 'test-results').glob('TEST-*.xml')):
    xml = ET.parse(path).getroot()
    assert all(int(xml.get(key, '0')) == 0 for key in ('failures', 'errors', 'skipped')), path.name
    cases = xml.findall('testcase')
    assert len(cases) == int(xml.get('tests')), path.name
    assert all(not any(case.find(key) is not None for key in ('failure', 'error', 'skipped')) for case in cases)
    name = xml.get('name').split('.')[-1]
    assert name not in suites
    suites[name] = {'tests': len(cases), 'cases': [case.get('name') for case in cases], 'file': relative(path)}
assert suites, 'Completed JUnit XML is required'
junit_total = sum(suite['tests'] for suite in suites.values())


def test(suite, method):
    selected = [name for name in suites[suite]['cases'] if name.startswith(method)]
    assert selected, (suite, method)
    return {'suite': suite, 'method': method, 'cases': selected, 'file': suites[suite]['file']}


def parameters(suite, method, expected):
    assert set(expected) <= set(suites[suite]['cases']), (suite, method, expected, suites[suite]['cases'])
    return {'suite': suite, 'method': method, 'cases': expected, 'file': suites[suite]['file']}


def expected_resolutions(variant):
    return {'CURRENT_NODE_RUNTIME': 'COMPATIBLE',
            'TARGET_NODE_RUNTIME': 'MISSING_METHOD' if variant == 'blocked' else 'COMPATIBLE',
            'TARGET_VERIFIER': 'COMPATIBLE' if variant == 'compatible' else 'MISSING_METHOD'}


def report_proof(report, variant):
    evidence = report['evidence']
    assert (report['sourceVersion'], report['targetVersion']) == ('4.11.6', '4.12.11')
    assert report['status'] == ('READY FOR TVU' if variant == 'compatible' else 'BLOCKED')
    discovery = evidence['discovery']
    assert (discovery['sourcePlatform'], discovery['targetPlatform']) == ('13', '140')
    assert discovery['currentCordappJars'] == discovery['targetCordappJars'] == 2
    host = evidence['environment']['host']
    assert host['currentJava'] == '1.8.0_242'
    assert evidence['schema-analysis']['safeSettings']['databaseVendor'] == 'PostgreSQL'
    schema = 'example_issuer' if variant == 'compatible' else 'ExampleSchema'
    assert evidence['schema-analysis']['safeSettings']['effectiveSchema'] == schema
    assert evidence['tvu-evidence-supplied'] is False
    tvu = evidence['tvu-summary']
    assert all(tvu.get(key) is None for key in ('processed', 'succeeded', 'failed'))
    assert tvu['detailedRecords'] == 0 and not tvu['rootCauses']
    required = evidence['required-symbol-resolution']
    assert required['complete'] is True
    records = [item for item in required['symbols'] if item['symbol']['owner'] == OWNER
               and item['symbol']['member'] == 'total' and item['symbol']['descriptor'] == DESCRIPTOR
               and item['symbol']['kind'] == 'METHOD']
    assert len(records) == 1, records
    record = records[0]
    assert record['resolution'] == ('COMPATIBLE' if variant == 'compatible' else 'MISSING_METHOD')
    contexts = {item['context']: item for item in record['contexts']}
    assert set(contexts) == set(CONTEXTS)
    for context, resolution in expected_resolutions(variant).items():
        item = contexts[context]
        assert item['resolution'] == resolution, (variant, context, item)
        assert item['proof']['classStatus'] == 'found'
        assert item['proof']['memberStatus'] == ('found' if resolution == 'COMPATIBLE' else 'absent')
        origins = item['proof']['artifacts']
        assert origins and all('companion-tool.jar' not in origin for origin in origins)
        if context == 'CURRENT_NODE_RUNTIME':
            assert any(origin.startswith('corda.jar!/lib/required-component.jar') for origin in origins)
        elif context == 'TARGET_NODE_RUNTIME':
            assert all('external-verifier.jar' not in origin for origin in origins)
        else:
            assert any('!/tools/external-verifier.jar' in origin for origin in origins)
    assert {source['sourceArtifact'] for source in record['sources']} == {SOURCE}
    assert len({source['sourceClass'] for source in record['sources']}) == 3
    assert all(source['sourceMethod'] == 'verify()V' and source['referenceType'] == 'INVOKESTATIC' for source in record['sources'])
    context_model = evidence['execution-contexts']
    assert context_model['targetVerifierPresence'] == 'PRESENT'
    assert context_model['verifierScopeComplete'] is True
    assert any('tools/external-verifier.jar' in component for component in context_model['targetVerifierComponents'])
    assert evidence['analysis-coverage']['status'] == 'PARTIAL'
    assert not any(f['category'] == 'API_COMPATIBILITY' and f['severity'] == 'UNKNOWN' for f in report['findings'])
    blockers = [f for f in report['findings'] if f['category'] == 'API_COMPATIBILITY' and f['severity'] == 'BLOCKED']
    assert len(blockers) == (0 if variant == 'compatible' else 1)
    for finding in blockers:
        assert finding['affectedArtifact'] == 'current/historical/' + SOURCE
        raw = finding['technicalEvidence']
        for exact in ('sourceScope: active-current-cordapp', 'sourceArtifact: ' + SOURCE, 'owner: ' + OWNER,
                      'descriptor: ' + DESCRIPTOR, 'resolution: missing-method'):
            assert exact in raw
        sources = [line.split(': ', 1)[1] for line in raw if re.match(r'sourceArtifact(?:\.\d+)?: ', line)]
        assert set(sources) == {SOURCE}
    return record


def bundle_proof(path, variant):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert {'checksums.sha256', 'assessment.json', 'required-symbol-resolution.json', 'execution-contexts.json', 'sanitized-node.conf'} <= set(names)
        for name in names:
            assert '/' not in name and '\\' not in name and not name.startswith('.')
            assert not name.lower().endswith(('.key', '.pem', '.jks', '.p12', '.pfx', '.jar', '.class', '.bin'))
            content = archive.read(name).decode('utf-8')
            assert not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', content)
            assert not any(secret in content for secret in ('SyntheticPasswordOnly42', 'SyntheticSecretOnly42'))
            if name.endswith('.json'):
                json.loads(content)
        report = json.loads(archive.read('assessment.json'))
        report_proof(report, variant)
        assert json.loads(archive.read('required-symbol-resolution.json')) == report['evidence']['required-symbol-resolution']
        assert json.loads(archive.read('execution-contexts.json')) == report['evidence']['execution-contexts']
        for line in archive.read('checksums.sha256').decode().splitlines():
            digest, name = line.split('  ', 1)
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    assert path.with_name(path.name + '.sha256').read_text().split()[0] == sha(path)
    return {'path': relative(path), 'sha256': sha(path), 'entries': len(names)}


def report_files(directory, variant):
    report = read(directory / 'report.json')
    record = report_proof(report, variant)
    for filename in ('report.html', 'summary.txt', 'technical-assessment.txt', 'required-symbol-resolution.json', 'execution-contexts.json', 'analysis-coverage.json'):
        assert (directory / filename).stat().st_size > 0, (directory, filename)
    assert read(directory / 'required-symbol-resolution.json') == report['evidence']['required-symbol-resolution']
    assert read(directory / 'execution-contexts.json') == report['evidence']['execution-contexts']
    packages = list(directory.glob('*-R3-support-*.zip'))
    assert len(packages) == 1, directory
    return record, [bundle_proof(path, variant) for path in packages]


def ansi(path):
    raw = path.read_bytes()
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8')).replace('\r', '')
    quiet(text)
    assert raw.rfind(b'\x1b[?25h') > raw.rfind(b'\x1b[?25l') >= 0
    return text


tarball_sha = sha(ROOT / 'ledger-preflight-0.1.0-linux-x86_64.tar.gz')
ubuntu, bundles = {}, []
matrix = ROOT / 'linux-matrix'
for version in VERSIONS:
    scenarios = {}
    for variant in VARIANTS:
        name = 'execution-context-' + variant + '-' + version
        directory = matrix / name
        record, shared = report_files(directory, variant)
        bundles.extend(shared)
        text = ansi(matrix / (name + '.ansi'))
        schema = 'example_issuer' if variant == 'compatible' else 'ExampleSchema'
        for expected in ('NODE DISCOVERED', 'ExampleIssuer', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140',
                         '1.8.0_242', 'PostgreSQL', schema, '2 current', '2 target', 'TVU          Found', '> Continue',
                         'Technical report exported', 'READY TO SHARE', 'Final package rescanned', 'Session complete'):
            assert expected in text, (version, variant, expected)
        assert 'View TVU evidence' not in text
        if variant == 'compatible':
            assert 'READY FOR TVU' in text and 'View compatibility evidence' not in text
        else:
            for expected in ('NOT READY TO UPGRADE', 'CorDapp compatibility', 'WHAT HAPPENED', 'WHY IT MATTERS', 'WHAT TO DO', 'SCHEMA EVIDENCE'):
                assert expected in text, (version, variant, expected)
            page = text.split('COMPATIBILITY EVIDENCE', 1)[1].split('> Back', 1)[0]
            affected = page.split('Affected CorDapp\n', 1)[1].split('\n\nReferenced API', 1)[0].strip()
            assert affected == 'example-old-contract.jar'
            assert page.count('Referenced API') == 1
            assert 'org.example.runtime.Amounts.total(Iterable)' in page
            for heading in ('Current runtime · Corda 4.11.6', 'Target runtime · Corda 4.12.11', 'Target verifier · Corda 4.12.11'):
                assert heading in page
            current, target = page.split('Target runtime', 1)
            node, verifier = target.split('Target verifier', 1)
            assert 'Class found · Method found' in current
            assert ('Class found · Method missing' if variant == 'blocked' else 'Class found · Method found') in node
            assert 'Class found · Method missing' in verifier
            for forbidden in ('Class missing', 'lookup incomplete', 'companion-tool.jar', 'external-verifier.jar', 'example-new-contract.jar', 'assessment\n'):
                assert forbidden not in page
        command = (matrix / (name + '.command.txt')).read_text().splitlines()
        assert command[0].endswith('/runtime/bin/java')
        assert [argument for argument in command if argument.startswith('-Xmx')] == ['-Xmx256m']
        assert '--tvu-results' not in command
        expected_exit = 1 if variant == 'compatible' else 2
        assert (matrix / (name + '.exit.txt')).read_text().strip() == str(expected_exit)
        assert (matrix / (name + '.tarball.sha256')).read_text().split()[0] == tarball_sha
        validation = (matrix / (name + '.validation.txt')).read_text()
        assert 'PASS' in validation and 'read-only node/kit' in validation and 'non-root' in validation
        scenarios[variant] = {'report': relative(directory / 'report.json'), 'contexts': expected_resolutions(variant), 'heap': '-Xmx256m', 'exit': expected_exit}
    for old_name in ('ubuntu-', 'discovery-terminal-', 'run-a-', 'active-runtime-', 'required-symbols-'):
        assert (matrix / (old_name + version + '.validation.txt')).stat().st_size > 0
    assert '8 environment/cursor cases passed' in (matrix / ('discovery-terminal-' + version + '.validation.txt')).read_text()
    ubuntu[version] = {'result': 'PASS', 'scenarios': scenarios}
assert 'Java8 unchanged' in (matrix / 'ubuntu-18.04-java8.validation.txt').read_text()
execution = read(ROOT / 'ubuntu-matrix-execution.json')
assert execution['result'] == 'PASS' and execution['network'] == 'none' and execution['rootFilesystem'] == 'read-only'
assert execution['user'] == '10001:10001' and execution['installedDependencies'] == []
assert set(execution['ubuntuImages']) == set(VERSIONS)
assert all(re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in execution['ubuntuImages'].values())

terminal = read(ROOT / 'execution-context-terminal-validation.json')
assert set(terminal) == {name for variant in VARIANTS for name in ('execution-context-' + variant, 'execution-context-' + variant + '-non-tty')}
for variant in VARIANTS:
    name = 'execution-context-' + variant
    case = terminal[name]
    assert case['exit'] == (1 if variant == 'compatible' else 2)
    assert all(case[key] is True for key in ('terminalRestored', 'cursorHiddenDuringMenu', 'cursorRestored', 'exactProofExported', 'sourceOnlyAttribution'))
    assert case['heap'] == '-Xmx256m'
    assert case['contextResolutions'] == expected_resolutions(variant)
    record, shared = report_files(ROOT / 'execution-context-artifacts' / variant, variant)
    bundles.extend(shared)
    ansi(ROOT / 'terminal-transcripts' / (name + '.ansi'))
    command = (ROOT / 'terminal-transcripts' / (name + '.command.txt')).read_text().splitlines()
    assert [argument for argument in command if argument.startswith('-Xmx')] == ['-Xmx256m']
    non_tty = terminal[name + '-non-tty']
    assert non_tty['exit'] == case['exit'] and non_tty['oneJsonDocument'] and non_tty['noCursorControls']
    raw = (ROOT / 'terminal-transcripts' / (name + '-non-tty.json')).read_bytes()
    assert b'\x1b[' not in raw
    report_proof(json.loads(raw), variant)

expected_screens = ('19-execution-context-environment.png', '20-execution-context-blocked.png', '21-execution-context-proof.png',
                    '22-execution-context-schema.png', '23-execution-context-export.png', '24-execution-context-support.png',
                    '25-execution-context-exit.png', '26-verifier-only-result.png', '27-verifier-only-proof.png', '28-execution-context-compatible.png')
manifest = read(ROOT / 'screenshots/manifest-execution-context.json')
assert {entry['file'] for entry in manifest} == set(expected_screens) and len(manifest) == len(expected_screens)
screenshots = []
for entry in manifest:
    path = ROOT / 'screenshots' / entry['file']
    assert sha(path) == entry['sha256'] and path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
    assert entry['source'] == 'actual Ubuntu PTY emulator cell buffer from the packaged launcher'
    text = path.with_name(path.name + '.txt').read_text()
    quiet(text)
    if entry['file'] in ('21-execution-context-proof.png', '27-verifier-only-proof.png'):
        assert all(term in text for term in ('example-old-contract.jar', 'Current runtime', 'Target runtime', 'Target verifier', 'Class found', 'Method found', 'Method missing'))
        assert 'example-new-contract.jar' not in text and 'Class missing' not in text
    screenshots.append({'path': relative(path), 'sha256': sha(path)})
old_manifest = read(ROOT / 'screenshots/manifest.json')
for entry in old_manifest:
    assert sha(ROOT / 'screenshots' / entry['file']) == entry['sha256']
unchanged = read(ROOT / 'unchanged-ux-proof.json')
assert unchanged['baselineCommit'] == '5bd7b9549aabb696416dc8c20283cbc13d5f59c9'
assert unchanged['environmentUnchanged'] is True and unchanged['legacySchemaCaseVerified'] is True

lookup, symbols, integration, ux = 'ExecutionContextLookupTest', 'ExecutionContextSymbolTest', 'ExecutionContextIntegrationTest', 'ExecutionContextUxTest'
acceptance = {}


def verified(letter, behavior, *evidence):
    acceptance[letter] = {'result': 'PASS', 'behavior': behavior, 'evidence': list(evidence)}


real_shape = parameters(integration, 'realShapeResolvesEachContextWithoutDriverOrVerifierAmbiguity', ['[1] true', '[2] false'])
legacy = parameters(integration, 'verifierLegacySelectionUsesProvenOrderOnly', ['[1] verifier-first', '[2] shim-first', '[3] unproven', '[4] contradictory'])
verified('A', 'Selected current runtime owns the API; supporting duplicates do not compete', test(lookup, 'selectedRuntimeWinsOverGenericSupportingDuplicate'), test('IndependentExecutionContextAuthorityTest', 'selectedRuntimeRoleCannotBeOverriddenByIncidentalVerifierEntryClass'), real_shape)
verified('B', 'Target node and verifier retain independent class/member proof', test(lookup, 'nodeAndNestedVerifierResolveIndependently'), test(symbols, 'contextInventoriesDoNotFlattenNodeAndVerifierCopies'), real_shape)
verified('C', 'Cross-context duplicate owners do not create generic ambiguity', test(symbols, 'nodeAndVerifierCopiesResolveIndependentlyAndGroupOneRemovedMethod'), '12 packaged context reports')
verified('D', 'Proven same-context ordering selects the winner and retains shadowed origins', test(lookup, 'explicitSameContextOrderSelectsWinningDefinitionAndRetainsShadowedOrigin'), test('IndependentExecutionContextOrderingTest', 'exactExtractedVerifierAndShimPathsBindWithoutFlatteningNodeCapsule'), legacy)
verified('E', 'Unproven same-context precedence affects only that context', test(lookup, 'unknownVerifierOrderingDoesNotMakeNodeUnknown'), test(integration, 'unorderedSameContextDoesNotMakeOtherContextsUnknown'), test(symbols, 'confirmedNodeBlockerSurvivesUnknownVerifier'), test(symbols, 'confirmedVerifierBlockerSurvivesUnknownNode'))
verified('F', 'Target CorDapp pairing uncertainty cannot downgrade runtime incompatibility', test(integration, 'targetPairingUnresolvedDoesNotDowngradeRuntimeProof'), test(ux, 'targetPairingUncertaintyIsASeparateReview'))
verified('G', 'Compatible APIs are quiet; unrelated workflows do not enter verifier scope', test(integration, 'compatibleStandardClassesAndWorkflowOnlyApisStayQuiet'), test(symbols, 'workflowOnlyReferencesAreNeverLookedUpInVerifier'), test('IndependentExecutionContextScopeTest', 'sharedHelperDoesNotPullUnrelatedWorkflowSubclassIntoVerifier'), 'four packaged compatible READY FOR TVU reports')
verified('H', 'Current runtime class and exact required method are found', real_shape, '12 packaged current context proofs')
verified('I', 'Target node class found with exact method missing is preserved', real_shape, 'four packaged blocked node proofs')
verified('J', 'Target verifier class found with exact method missing is preserved', test(integration, 'nodeCompatibleVerifierMissingIsAConfirmedVerifierBlocker'), 'eight packaged incompatible verifier proofs')
verified('K', 'Confirmed removal remains a compatibility blocker with one grouped root', test(symbols, 'nodeAndVerifierCopiesResolveIndependentlyAndGroupOneRemovedMethod'), 'eight packaged BLOCKED reports')
verified('L', 'Only active current source CorDapps are affected, including verifier-specific caller scope', test(symbols, 'verifierOnlyFailureDoesNotAttributeCompatibleWorkflowArtifact'), test(symbols, 'allSourceCallersAreRetainedButNeverRuntimeOrVerifierAsAffectedArtifacts'), 'eight packaged source-only affected-artifact assertions')
verified('M', 'Verifier-first shadowing blocks the shim; shim-first and unproven order remain distinct', legacy, test(lookup, 'verifierWinsBeforeLegacyShimWhenActualOrderIsKnown'), test(lookup, 'verifierWithoutOrderCannotAssumeLegacyLoses'))
verified('N', 'Unrelated broad PARTIAL never downgrades completed required context lookups', test(integration, 'broadPartialDoesNotDowngradeSuccessfulExactContexts'), '12 packaged PARTIAL plus complete required-symbol proofs')
verified('O', 'Packaged Continue/evidence/export/support runs at actual -Xmx256m', *[relative(path) for path in sorted(matrix.glob('execution-context-*.command.txt'))])
verified('P', 'Environment values and original source remain unchanged', test('SimpleResultActionsTest', 'environmentUsesSelectedRuntimeAndHidesHistoricalDetails'), 'unchanged-ux-proof.json', 'screenshots/19-execution-context-environment.png', '12 packaged Environment screens')
verified('Q', 'Existing blocked-schema wording and structure remain unchanged; automatic setup has a separate branch', test(ux, 'schemaWordingAndStructureRemainUnchangedWithContextFindings'), 'unchanged-ux-proof.json', 'screenshots/22-execution-context-schema.png')
verified('R', 'Human context proof and verifier-only explanation expose no raw diagnostic noise', test(ux, 'allThreeProofsDescribeTheActualMissingMethod'), test(ux, 'verifierOnlyFailureDoesNotClaimTheNodeMethodIsMissing'), test(ux, 'confirmedRootPrecedesSeparateUnknownReferencesAndKeepsItsSource'), *screenshots)
verified('S', 'HTML/JSON/text and structured exports retain exact context-specific proof', test(integration, 'exportsContainIndependentProofWithoutAbsoluteInputPaths'), test(ux, 'exportedProofKeepsExactContextsAndSourceWhileNormalOutputStaysShort'), '12 packaged report directories and three PTY export directories')
verified('T', 'Support packages retain context proof, exclude private material, and verify final checksums', test('EvidenceTest', 'finalScannerFailsClosedAndProducesNoZip'), test('EvidenceTest', 'structuredSecretValuesRedactedWithoutBreakingJson'), *bundles)
assert set(acceptance) == set('ABCDEFGHIJKLMNOPQRST')
legacy_terminals = read(ROOT / 'interactive-validation.json')
legacy_cli = sum(sum('exit' in value for value in read(ROOT / name).values()) for name in ('cli-smoke-validation.json', 'universality-validation.json', 'product-correction-validation.json'))
totals = {'junit': junit_total, 'legacyCliProcesses': legacy_cli, 'newContextNonTtyProcesses': 3,
          'legacyTerminalAndPipeCases': len(legacy_terminals), 'newContextTerminalAndPipeCases': len(terminal),
          'ubuntuContextPtyCases': len(VERSIONS) * len(VARIANTS), 'newSupportPackages': len(bundles),
          'legacyScreenshots': len(old_manifest), 'newScreenshots': len(manifest)}
result = {'acceptance': acceptance, 'totals': totals, 'junitTotal': junit_total, 'testIndex': suites,
          'ubuntu': ubuntu, 'ubuntuExecution': execution, 'java8Coexistence': 'PASS: existing Java 8 unchanged',
          'supportPackages': bundles, 'screenshots': screenshots, 'tarballSha256': tarball_sha,
          'scope': 'Synthetic contexts and actual final standalone executions; manual real Run A remains required.'}
(ROOT / 'execution-context-validation.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'acceptance': {key: value['result'] for key, value in acceptance.items()}, 'totals': totals,
                  'ubuntu': {key: value['result'] for key, value in ubuntu.items()}, 'tarballSha256': tarball_sha}, indent=2))
