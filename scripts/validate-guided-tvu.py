"""Cross-validate A–AH against actual JUnit, packaged Ubuntu and captured CLI evidence."""
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path('/dist')
VERSIONS = ('18.04', '20.04', '22.04', '24.04')
SECRET = 'SyntheticGuidedCredential42'


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def input_hashes(root):
    return {str(path.relative_to(root)): sha(path) for name in ('node', 'kit')
            for path in sorted((root / name).rglob('*')) if path.is_file()}


def report_proof(assessment, mode, guided=True):
    assert (assessment['sourceVersion'], assessment['targetVersion']) == ('4.11.6', '4.12.11')
    failed = mode in ('failed', 'imported')
    assert assessment['status'] == ('BLOCKED' if failed else 'READY TO UPGRADE')
    evidence = assessment['evidence']
    assert evidence['tvu-evidence-supplied'] is True
    schema = evidence['schema-analysis']['safeSettings']['tvuSchemaReadiness']
    assert schema['status'] == 'HANDLED' and schema['proven'] is True
    assert evidence['tvu-schema-execution']['handled'] is True
    tvu = evidence['tvu-summary']
    assert (tvu['processed'], tvu['succeeded'], tvu['failed']) == ((650, 449, 201) if failed else (650, 650, 0))
    assert tvu['detailedRecords'] == (201 if failed else 0)
    if failed:
        assert len(tvu['rootCauses']) == 1 and list(tvu['rootCauses'].values()) == [201]
    blockers = [value for value in assessment['findings'] if value['severity'] == 'BLOCKED']
    assert {value['category'] for value in blockers} == ({'API_COMPATIBILITY', 'TVU'} if failed else set())
    for finding in blockers:
        if finding['category'] == 'API_COMPATIBILITY':
            assert finding['affectedArtifact'] == 'current/historical/cordapps/example-old-contract.jar'
    assert not any(value['id'] == 'LP-API-003' for value in assessment['findings'])
    proof = evidence['required-symbol-resolution']
    assert proof['complete'] is True
    ordinary = [item for item in proof['symbols'] if item['symbol']['owner'] == 'org/example/runtime/OrdinaryType' and item['symbol']['kind'] == 'CLASS']
    assert len(ordinary) == 1 and ordinary[0]['resolution'] == 'COMPATIBLE'
    if guided:
        run = evidence['tvu-run']
        assert run['configurationSource'] in ('current node', 'explicit alternate')
        assert run['databaseTarget'] == 'jdbc:postgresql://database.example/' + ('alternate_copy' if run['configurationSource'] == 'explicit alternate' else 'isolated_copy')
        assert re.fullmatch('[0-9a-f]{64}', run['sanitizedConfigurationSha256'])
        assert run['workspaceCleaned'] is True and run['cancelled'] is False
        assert run['exitCode'] == 0
        assert run['failureKind'] == ('TRANSACTION_VERIFICATION_FAILURE' if failed else 'NONE')
        assert run['schemaApplied'] is True and run['schema'] == 'ExampleSchema'
        assert run['targetVersion'] == run['tvuVersion'] == '4.12.11'
        assert any(item['role'] == 'TVU' for item in run['artifacts'])
        assert len([item for item in run['artifacts'] if item['role'] == 'CORDAPP']) == 2
        assert '[PRIVATE-WORKSPACE]' in run['classpath']
        assert any(name.endswith('.log') for name in run['evidence'])
        assert any(name.endswith('.zip') for name in run['evidence']) is failed
    assert SECRET not in json.dumps(assessment)
    return assessment


def check_bundle(path, mode):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert {'assessment.json', 'required-symbol-resolution.json', 'execution-contexts.json', 'schema-analysis.json',
                'tvu-summary.json', 'tvu-schema-execution.json', 'sanitized-node.conf', 'checksums.sha256'} <= set(names)
        if mode != 'imported':
            assert 'tvu-run.json' in names
        for name in names:
            assert '/' not in name and '\\' not in name and not name.startswith('.')
            assert not name.lower().endswith(('.key', '.pem', '.jks', '.p12', '.pfx', '.jar', '.class', '.bin'))
            text = archive.read(name).decode()
            assert SECRET not in text and not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', text)
            if name.endswith('.json'):
                json.loads(text)
        assessment = report_proof(json.loads(archive.read('assessment.json')), mode, mode != 'imported')
        for name, key in (('tvu-summary.json', 'tvu-summary'), ('tvu-schema-execution.json', 'tvu-schema-execution')):
            assert json.loads(archive.read(name)) == assessment['evidence'][key]
        for line in archive.read('checksums.sha256').decode().splitlines():
            digest, name = line.split('  ', 1)
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    assert path.with_name(path.name + '.sha256').read_text().split()[0] == sha(path)
    return {'path': str(path.relative_to(ROOT)), 'sha256': sha(path)}


def validate_session(directory, mode):
    reports = [path for path in directory.glob('*/report.json') if path.parent.name.startswith(('validated-', 'imported-tvu-'))]
    assert reports
    for path in reports:
        assessment = report_proof(read(path), mode, mode != 'imported')
        if mode != 'imported':
            assert assessment['evidence']['tvu-run']['configurationSource'] == ('explicit alternate' if mode == 'failed' else 'current node')
    bundles = list(directory.glob('*-R3-support-*.zip'))
    assert len(bundles) == 1
    assert any(path.stat().st_size for path in directory.glob('*/technical-assessment.txt'))
    assert not list(directory.rglob('.workspace-*'))
    return check_bundle(bundles[0], mode)


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
    bundles, ubuntu = [], {}
    for version in VERSIONS:
        for mode in ('failed', 'success'):
            stem = ROOT / 'linux-matrix' / ('guided-tvu-' + mode + '-' + version)
            report_proof(read(stem.with_name(stem.name + '.json')), mode)
            report_proof(read(stem / 'report.json'), mode)
            assert read(stem / 'tvu-run.json')['configurationSource'] == 'current node'
            bundles.append(check_bundle(stem / 'support.zip', mode))
            static = read(stem.with_name(stem.name + '.static.json'))
            assert static['status'] == ('BLOCKED' if mode == 'failed' else 'READY FOR TVU')
            assert static['evidence']['tvu-evidence-supplied'] is False and 'tvu-run' not in static['evidence']
            assert static['evidence']['schema-analysis']['safeSettings']['tvuSchemaReadiness']['status'] == 'AUTO_CONFIGURABLE'
            refused = stem.with_name(stem.name + '.refused.stderr').read_text()
            assert '--confirm-isolated-db' in refused and 'No TVU process was started' in refused
            assert not stem.with_name(stem.name + '.refused.stdout').read_bytes()
            assert stem.with_name(stem.name + '.inputs-before.sha256').read_bytes() == stem.with_name(stem.name + '.inputs-after.sha256').read_bytes()
            observation = (stem.with_name(stem.name + '.observations') / 'observed.properties').read_text()
            assert all(value in observation for value in ('-Xmx256m', 'workspaceMode=rwx------', 'configMode=rw-------', 'loadedSchema="ExampleSchema"'))
            observed = dict(line.split('=', 1) for line in observation.splitlines() if '=' in line and not line.startswith('#'))
            assert observed['javaHome'] == '/tmp/lp/ledger-preflight-0.1.0/runtime'
            assert observed['environmentJavaHome'] == observed['javaHome']
            assert observed['javaVersion'].startswith('17.') and 'openjdk version "17.' in observed['bareJavaVersion']
            assert stem.with_name(stem.name + '.exit.txt').read_text().strip() == ('2' if mode == 'failed' else '0')
            assert stem.with_name(stem.name + '.tarball.sha256').read_text().split()[0] == tarball
            assert 'PASS' in stem.with_name(stem.name + '.validation.txt').read_text()
            assert not list(stem.rglob('.workspace-*'))
        ubuntu[version] = 'PASS'

    terminal = read(ROOT / 'guided-tvu-terminal-validation.json')
    for name in ('failed', 'success', 'imported', 'cancel'):
        assert all(terminal[name][field] is True for field in ('terminalRestored', 'inputsUnchanged', 'noOrphanProcesses', 'workspaceCleaned'))
        assert terminal[name]['heap'] == '-Xmx256m'
        raw = (ROOT / 'terminal-transcripts' / ('guided-tvu-' + name + '.ansi')).read_bytes()
        assert raw.rfind(b'\x1b[?25h') > raw.rfind(b'\x1b[?25l') >= 0
        assert SECRET.encode() not in raw and b'External verifier process started' not in raw
        if name != 'cancel':
            bundles.append(validate_session(ROOT / 'guided-tvu-artifacts' / name, name))
    assert terminal['refusedInteractive'] == {'noProcess': True, 'noWorkspace': True}
    assert terminal['refusedNoninteractive']['noProcess'] is True
    assert terminal['cancel']['partialEvidenceRetained'] is True
    screenshots = read(ROOT / 'screenshots/manifest-guided-tvu.json')
    assert len(screenshots) == 17
    assert {int(item['file'].split('-')[0]) for item in screenshots} == set(range(50, 67))
    for item in screenshots:
        path = ROOT / 'screenshots' / item['file']
        assert sha(path) == item['sha256'] and path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
        assert 'actual Ubuntu PTY emulator cell buffer' in item['source']
        assert SECRET not in path.with_name(path.name + '.txt').read_text()
    assert len(bundles) == 11

    cli, safe, lifecycle, schema = 'GuidedTvuCliTest', 'IndependentGuidedTvuSafetyTest', 'IndependentGuidedTvuLifecycleTest', 'TvuSchemaExecutionTest'
    mapping = [
        ('A', 'Static assessment starts no TVU or database process.', [case(safe, 'staticAssessmentAndInspectionNeverStartProcessOrPrepareWorkspace'), case(cli, 'staticCliNeverExecutesTvuEvenWhenAnIsolationFlagIsPresent')]),
        ('B', 'Result actions expose guided TVU safely.', [case(cli, 'failedGuidedRunAutomaticallyImportsZipAndCorrelatesAllFailures'), 'screenshots/51-guided-tvu-static-result.png']),
        ('C', 'Declining confirmation creates no workspace or process.', [case(safe, 'unconfirmedDatabaseNamedIsolatedCopyStillCannotStart'), terminal['refusedInteractive'], terminal['refusedNoninteractive']]),
        ('D', 'Affirmative confirmation prepares a private workspace.', [case(safe, 'confirmedRunPreparesPrivateInputsLoadsSchemaAndCleansWorkspace')]),
        ('E', 'Alternate safe configuration requires fresh confirmation.', [case(cli, 'alternateConfigurationRequiresANewAffirmativeConfirmation'), case(safe, 'compatibleAlternateConfigurationCanBeUsedWithoutChangingIt')]),
        ('F', 'Credentials are absent from progress, arguments and exported evidence.', [case(safe, 'emittedCredentialIsRedactedFromAllPreservedTextAndProgress'), bundles]),
        ('G', 'Source node bytes remain unchanged.', [case(safe, 'confirmedRunPreparesPrivateInputsLoadsSchemaAndCleansWorkspace'), ubuntu]),
        ('H', 'Upgrade kit bytes remain unchanged.', [case(safe, 'changedTargetArtifactCannotRunAfterApprovalOfItsPreviousBytes'), ubuntu]),
        ('I', 'Known mixed-case schema is prepared and actual loaded proof is analyzed.', [case(safe, 'confirmedRunPreparesPrivateInputsLoadsSchemaAndCleansWorkspace'), 'screenshots/58-guided-tvu-schema-handled.png']),
        ('J', 'Established primary schema wins over additional search-path entries.', [case(schema, 'primaryIsUsedAndExplicitUnknownSelectionIsRejected')]),
        ('K', 'Ambiguous schema requires a discovered candidate; cancellation is safe.', [case(cli, 'ambiguousSchemaSelectionPrecedesDatabaseConfirmationAndCanBeCancelled')]),
        ('L', 'Packaged private Java runs TVU without host Java installation.', [ubuntu]),
        ('M', 'Validator descendants inherit the private Java context.', [case(lifecycle, 'explicitCancellationStopsParentChildGrandchildAndRemovesPrivateWorkspace')]),
        ('N', 'SIGINT cleans the validator process group and private configuration.', [case(lifecycle, 'sigintOfLedgerPreflightCleansProcessGroupAndTemporaryConfiguration')]),
        ('O', 'Raw verifier retry noise remains outside normal terminal output.', [case(cli, 'unknownProgressNeverInventsATransactionTotalOrRepeatsRawNoise'), terminal]),
        ('P', 'Progress displays only actual observed counts.', [case(cli, 'observedProgressShowsOnlyActualCountersAndElapsedTime'), 'screenshots/54-guided-tvu-progress.png']),
        ('Q', 'Generated TVU error ZIP is discovered and analyzed automatically.', [case(safe, 'actualErrorZipAndLogsAreDiscoveredAndAll201FailuresCorrelate')]),
        ('R', 'Generated TVU log evidence is retained and analyzed automatically.', [case(safe, 'actualErrorZipAndLogsAreDiscoveredAndAll201FailuresCorrelate')]),
        ('S', 'Actual synthetic TVU reports 650 processed, 449 passed and 201 failed.', [case(safe, 'actualErrorZipAndLogsAreDiscoveredAndAll201FailuresCorrelate'), ubuntu]),
        ('T', 'All 201 supplied failures correlate to the source compatibility blocker.', [case(cli, 'failedGuidedRunAutomaticallyImportsZipAndCorrelatesAllFailures')]),
        ('U', 'Matching loaded Hibernate property makes schema handling HANDLED.', [case(schema, 'importedActualLoadedProofAndSuccessCanEstablishReadiness'), bundles]),
        ('V', 'Actual schema failure remains blocked despite earlier loaded configuration.', [case(safe, 'realSchemaFailureOverridesSuccessfullyLoadedConfiguration')]),
        ('W', 'Existing --tvu-results behavior remains evidence based.', [case(schema, 'importedResultsNeedActualLoadedProofEvenWithQuotedNodeConfiguration')]),
        ('X', 'Interactive import updates the assessment without starting TVU.', [case(cli, 'interactiveImportAcceptsLogAndZipAndUpdatesTheCurrentResult'), terminal['imported']]),
        ('Y', 'Required legacy JARs are copied into the private TVU workspace.', [case(safe, 'approvedExecutionCopiesSuppliedLegacyJarsWithoutChangingThem')]),
        ('Z', 'Existing confirmed legacy shadowing remains visible.', [case(safe, 'confirmedLegacyShadowingRemainsAnExplicitGuidedRunWarning')]),
        ('AA', 'Completion and cancellation leave no observed validator descendants.', [case(lifecycle, 'normalParentCompletionStillReapsTheSyntheticVerifierDescendants'), terminal['cancel']]),
        ('AB', 'Timeout and cancellation remove sensitive temporary workspace files.', [case(lifecycle, 'timeLimitCleansEveryObservedDescendantAndSensitiveFiles'), terminal['cancel']]),
        ('AC', 'R3 packages include sanitized guided evidence and verified SHA-256.', [case(cli, 'supportActionCollectsGuidedRunEvidenceWithoutManualFileGathering'), case(cli, 'cliSupportCreatesVerifiedChecksumAndRefusesExistingChecksum'), bundles]),
        ('AD', 'A second approved TVU run works in the same assessment session.', [case(cli, 'anotherGuidedRunCanExecuteFromTheSameAssessmentSession'), terminal['failed']]),
        ('AE', 'Compatible static input waits in READY FOR TVU.', ['screenshots/62-guided-tvu-ready-for-tvu.png', ubuntu]),
        ('AF', 'Complete successful validation permits READY TO UPGRADE.', [case(cli, 'confirmedNoninteractiveRunEmitsOneFinalJsonAssessment'), 'screenshots/63-guided-tvu-ready-to-upgrade.png']),
        ('AG', 'Failed, cancelled or incomplete capture cannot claim readiness.', [case(cli, 'completeCountersCannotOverrideFinalCaptureOrCleanupFailure'), terminal['cancel']]),
        ('AH', 'All four Ubuntu releases execute the shipped package at -Xmx256m.', [ubuntu, tarball]),
    ]
    assert len(mapping) == 34
    result = {'acceptance': {key: {'result': 'PASS', 'behavior': behavior, 'evidence': evidence} for key, behavior, evidence in mapping},
              'junitTotal': sum(value['tests'] for value in suites.values()), 'testIndex': suites, 'ubuntu': ubuntu,
              'newSupportPackages': bundles, 'screenshots': screenshots, 'terminalCases': terminal, 'tarballSha256': tarball,
              'scope': 'Original synthetic executable TVU and actual Docker package validation. No real database was contacted; isolated real-environment guided TVU remains required.'}
    (ROOT / 'guided-tvu-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'acceptance': {key: 'PASS' for key, _, _ in mapping}, 'junitTotal': result['junitTotal'], 'ubuntu': ubuntu,
                      'newSupportPackages': len(bundles), 'screenshots': len(screenshots), 'tarballSha256': tarball}, indent=2))


if __name__ == '__main__':
    main()
