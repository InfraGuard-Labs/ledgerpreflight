"""Capture real packaged execution-context CLI sessions in Ubuntu PTYs.

PNG text comes only from the terminal emulator cell buffer. Raw ANSI transcripts,
cell buffers, process arguments, exported assessments and support packages remain
available alongside the checks. Run inside the Docker terminal QA environment.
"""
import codecs
import fcntl
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import shutil
import struct
import subprocess
import termios
import time
import zipfile

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path('/dist')
WORK = pathlib.Path('/work/execution-context')
SHOTS = ROOT / 'screenshots'
TRANSCRIPTS = ROOT / 'terminal-transcripts'
OUTPUT = ROOT / 'execution-context-artifacts'
LAUNCHER = os.environ.get('LP_TEST_LAUNCHER', '/tmp/run-a-package/ledger-preflight-0.1.0/ledger-preflight')
assert pathlib.Path(LAUNCHER).is_file(), 'Extract the final standalone tarball before running this capture.'
assert 'ID=ubuntu' in pathlib.Path('/etc/os-release').read_text()
assert os.uname().machine == 'x86_64'
for directory in (WORK, SHOTS, TRANSCRIPTS, OUTPUT):
    directory.mkdir(parents=True, exist_ok=True)
FONT = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 18)
OWNER = 'org/example/runtime/Amounts'
DESCRIPTOR = '(Ljava/lang/Iterable;)Ljava/math/BigDecimal;'
results = {}
manifest = []


def quiet(text):
    for forbidden in ('C:\\Users', 'LP-API', 'LP-INPUT', 'LP-ANALYSIS', 'Ljava/', 'CURRENT_NODE_RUNTIME',
                      'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER', 'currentInventory', 'targetInventory',
                      'View technical evidence', 'View full technical report', 'REQUIRED_OR_UNRESOLVED',
                      'Analyzer:', 'SyntheticPasswordOnly42', 'OutOfMemoryError', 'Exception in thread'):
        assert forbidden not in text, forbidden
    assert not re.search(r'\d+ warnings', text)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class Terminal:
    def __init__(self, variant):
        self.variant = variant
        self.name = 'execution-context-' + variant
        self.cols, self.rows = 96, 56
        self.data = bytearray()
        self.decoder = codecs.getincrementaldecoder('utf8')('replace')
        self.screen = pyte.Screen(self.cols, self.rows)
        self.stream = pyte.Stream(self.screen)
        self.base = WORK / variant
        self.output = OUTPUT / variant
        self.command = [LAUNCHER, 'assess', '--node', str(self.base / 'ExampleIssuer'),
                        '--upgrade-kit', str(self.base / 'kit'), '--host-environment', str(self.base / 'host.json'),
                        '--verifier-classpath', str(self.base / 'classpath.txt'), '--network-mode', 'all-4.12',
                        '--output', str(self.output)]
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ.update(TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8')
            os.environ.pop('CI', None)
            os.execvp(self.command[0], self.command)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', self.rows, self.cols, 0, 0))

    def read(self, timeout=.1):
        if not select.select([self.fd], [], [], timeout)[0]:
            return False
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        self.data.extend(data)
        self.stream.feed(self.decoder.decode(data))
        return True

    def until(self, expected, timeout=90):
        start, end = len(self.data), time.monotonic() + timeout
        while time.monotonic() < end:
            if expected.encode() in self.data[start:]:
                while self.read(.15):
                    pass
                return
            self.read(.15)
        raise AssertionError(f'Missing {expected} in {self.name}\n' + self.data.decode(errors='replace')[-2500:])

    def display(self):
        return '\n'.join(self.screen.display)

    def menu(self):
        self.until('Up/Down')
        assert '> ' in self.display()
        assert self.screen.cursor.hidden and b'\x1b[?25l' in self.data
        assert not any(marker in self.display() for marker in ('❯', '□', '■', '▶'))
        quiet(self.display())

    def action(self, label):
        lines = list(self.screen.display)
        first = max(i for i, line in enumerate(lines) if line.startswith('> '))
        choices = []
        for line in lines[first:]:
            if 'Up/Down' in line:
                break
            choices.append(line[2:].strip())
        assert label in choices, (self.name, label, choices)
        index = choices.index(label)
        if index:
            os.write(self.fd, b'\x1b[B' * index)
            self.until('Up/Down')
        os.write(self.fd, b'\r')

    def capture(self, name, label):
        lines = self.screen.display
        quiet('\n'.join(lines))
        bottom = max((i for i, line in enumerate(lines) if line.strip()), default=0) + 2
        image = Image.new('RGB', (self.cols * 11 + 40, bottom * 27 + 32), (31, 24, 36))
        draw = ImageDraw.Draw(image)
        for row, line in enumerate(lines[:bottom]):
            draw.text((20, 16 + row * 27), line, font=FONT, fill=(245, 241, 247))
        path = SHOTS / name
        image.save(path)
        path.with_suffix(path.suffix + '.txt').write_text('\n'.join(lines[:bottom]) + '\n')
        manifest.append({'file': name, 'label': label, 'session': self.name,
                         'source': 'actual Ubuntu PTY emulator cell buffer from the packaged launcher',
                         'columns': self.cols, 'rows': self.rows,
                         'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

    def record_heap(self):
        arguments = pathlib.Path(f'/proc/{self.pid}/cmdline').read_bytes().split(b'\0')
        assert [a for a in arguments if a.startswith(b'-Xmx')] == [b'-Xmx256m'], arguments
        (TRANSCRIPTS / (self.name + '.command.txt')).write_bytes(b'\n'.join(arguments))

    def finish(self, expected):
        end = time.monotonic() + 60
        while time.monotonic() < end:
            self.read(.1)
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                while self.read(.05):
                    pass
                code = os.waitstatus_to_exitcode(status)
                assert code == expected, (self.name, code, expected)
                attrs = termios.tcgetattr(self.fd)
                assert attrs[3] & termios.ECHO and attrs[3] & termios.ICANON
                assert self.data.rfind(b'\x1b[?25h') > self.data.rfind(b'\x1b[?25l')
                assert not self.screen.cursor.hidden
                quiet(self.data.decode(errors='replace'))
                assert b'Session complete' in self.data
                assert b'View TVU evidence' not in self.data
                for invented in (b'650 processed', b'201 failed', b'Transactions processed'):
                    assert invented not in self.data
                (TRANSCRIPTS / (self.name + '.ansi')).write_bytes(self.data)
                os.close(self.fd)
                results[self.name] = {'exit': code, 'heap': '-Xmx256m', 'terminalRestored': True,
                                      'cursorHiddenDuringMenu': True, 'cursorRestored': True}
                return
        os.kill(self.pid, 9)
        raise AssertionError('Session failed to exit: ' + self.name)


def validate_export(variant, directory):
    for filename in ('report.html', 'report.json', 'summary.txt', 'technical-assessment.txt', 'required-symbol-resolution.json', 'execution-contexts.json'):
        assert (directory / filename).stat().st_size > 0, filename
    assessment = json.loads((directory / 'report.json').read_text())
    required = json.loads((directory / 'required-symbol-resolution.json').read_text())
    assert required['complete'] is True
    matches = [entry for entry in required['symbols'] if entry['symbol']['owner'] == OWNER
               and entry['symbol']['member'] == 'total' and entry['symbol']['descriptor'] == DESCRIPTOR]
    assert len(matches) == 1
    symbol = matches[0]
    contexts = {entry['context']: entry for entry in symbol['contexts']}
    assert set(contexts) == {'CURRENT_NODE_RUNTIME', 'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER'}
    expected = {'CURRENT_NODE_RUNTIME': 'COMPATIBLE',
                'TARGET_NODE_RUNTIME': 'MISSING_METHOD' if variant == 'blocked' else 'COMPATIBLE',
                'TARGET_VERIFIER': 'COMPATIBLE' if variant == 'compatible' else 'MISSING_METHOD'}
    for context, resolution in expected.items():
        proof = contexts[context]['proof']
        assert contexts[context]['resolution'] == resolution, (variant, context, contexts[context])
        assert proof['classStatus'] == 'found'
        assert proof['memberStatus'] == ('found' if resolution == 'COMPATIBLE' else 'absent')
        assert all('companion-tool.jar' not in origin for origin in proof['artifacts'])
        if context == 'TARGET_NODE_RUNTIME':
            assert all('external-verifier.jar' not in origin for origin in proof['artifacts'])
        if context == 'TARGET_VERIFIER':
            assert any('external-verifier.jar' in origin for origin in proof['artifacts'])
    assert assessment['status'] == ('READY FOR TVU' if variant == 'compatible' else 'BLOCKED')
    blockers = [finding for finding in assessment['findings'] if finding['category'] == 'API_COMPATIBILITY'
                and finding['severity'] == 'BLOCKED' and 'owner: ' + OWNER in finding['technicalEvidence']]
    assert len(blockers) == (0 if variant == 'compatible' else 1)
    for finding in blockers:
        assert 'sourceScope: active-current-cordapp' in finding['technicalEvidence']
        sources = [item.split(': ', 1)[1] for item in finding['technicalEvidence'] if re.match(r'sourceArtifact(?:\.\d+)?: ', item)]
        assert sources and all(pathlib.PurePosixPath(path).name == 'example-old-contract.jar' for path in sources)
    assert not any(f['severity'] == 'UNKNOWN' and f['category'] == 'API_COMPATIBILITY' for f in assessment['findings'])
    bundles = list(directory.glob('*-R3-support-*.zip'))
    assert len(bundles) == 1
    bundle = bundles[0]
    digest = file_hash(bundle)
    assert bundle.with_suffix('.zip.sha256').read_text().split()[0] == digest
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        assert not any(pathlib.PurePosixPath(name).suffix.lower() in {'.jks', '.p12', '.pfx', '.pem', '.key'} for name in names)
        assert not any(name.startswith('/') or '..' in pathlib.PurePosixPath(name).parts for name in names)
        proof_files = [name for name in names if pathlib.PurePosixPath(name).name == 'required-symbol-resolution.json']
        assert len(proof_files) == 1
        assert 'execution-contexts.json' in names
        shared = json.loads(archive.read(proof_files[0]))
        shared_symbol = next(entry for entry in shared['symbols'] if entry['symbol'] == symbol['symbol'])
        assert shared_symbol['contexts'] == symbol['contexts']
        for name in names:
            contents = archive.read(name)
            for secret in (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----', b'SyntheticPasswordOnly42'):
                assert secret not in contents, (name, secret)
    return {'status': assessment['status'], 'contextResolutions': expected, 'exactProofExported': True,
            'sourceOnlyAttribution': True, 'supportBundle': bundle.name, 'supportSha256': digest}


for variant in ('blocked', 'verifier-only', 'compatible'):
    source = ROOT / 'synthetic/execution-context' / variant
    destination = WORK / variant
    destination.mkdir()
    shutil.copytree(source / 'node', destination / 'ExampleIssuer')
    shutil.copytree(source / 'kit', destination / 'kit')
    for name in ('host.json', 'classpath.txt'):
        shutil.copyfile(source / name, destination / name)
    terminal = Terminal(variant)
    terminal.menu()
    terminal.record_heap()
    schema = 'example_issuer' if variant == 'compatible' else 'ExampleSchema'
    for expected in ('NODE DISCOVERED', 'ExampleIssuer', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140',
                     '1.8.0_242', 'PostgreSQL', schema, '2 current', '2 target', 'TVU          Found', '> Continue'):
        assert expected in terminal.display(), (variant, expected)
    if variant == 'blocked':
        terminal.capture('19-execution-context-environment.png', 'Unchanged Environment screen')
    terminal.action('Continue')
    terminal.menu()
    assert 'Compatibility analysis incomplete' not in terminal.display()
    if variant == 'compatible':
        assert 'READY FOR TVU' in terminal.display() and 'View compatibility evidence' not in terminal.display()
        terminal.capture('28-execution-context-compatible.png', 'Compatible APIs across runtime and verifier contexts')
    else:
        assert 'NOT READY TO UPGRADE' in terminal.display() and 'CorDapp compatibility' in terminal.display()
        if variant == 'verifier-only':
            assert 'not available in the target verifier.' in terminal.display()
        terminal.capture('20-execution-context-blocked.png' if variant == 'blocked' else '26-verifier-only-result.png',
                         'Confirmed node and verifier incompatibility' if variant == 'blocked' else 'Verifier-only incompatibility')
        terminal.action('View compatibility evidence')
        terminal.menu()
        text = terminal.display()
        for expected in ('COMPATIBILITY EVIDENCE', 'example-old-contract.jar', 'org.example.runtime.Amounts.total(Iterable)',
                         'Current runtime', 'Target runtime', 'Target verifier', 'Class found', 'Method found', 'Method missing', 'Impact'):
            assert expected in text, (variant, expected)
        node = text[text.index('Target runtime'):text.index('Target verifier')]
        verifier = text[text.index('Target verifier'):text.index('Impact')]
        assert ('Method missing' if variant == 'blocked' else 'Method found') in node
        assert 'Method missing' in verifier
        for forbidden in ('example-new-contract.jar', 'companion-tool.jar', 'external-verifier.jar', 'renamed-runtime.bin', 'Class missing', 'lookup incomplete'):
            assert forbidden not in text, forbidden
        terminal.capture('21-execution-context-proof.png' if variant == 'blocked' else '27-verifier-only-proof.png',
                         'Exact current, target node and target verifier proof')
        terminal.action('Back')
        terminal.menu()
        terminal.action('View schema evidence')
        terminal.menu()
        for expected in ('SCHEMA EVIDENCE', 'Database', 'PostgreSQL', 'Primary / effective schema', 'ExampleSchema',
                         'What LedgerPreflight found', 'Why this matters', 'Recommended action'):
            assert expected in terminal.display(), expected
        if variant == 'blocked':
            terminal.capture('22-execution-context-schema.png', 'Unchanged schema evidence')
        terminal.action('Back')
        terminal.menu()
    terminal.action('Export full technical report')
    terminal.menu()
    assert 'Technical report exported' in terminal.display()
    if variant == 'blocked':
        terminal.capture('23-execution-context-export.png', 'Full technical assessment exported')
    terminal.action('Back')
    terminal.menu()
    terminal.action('Create R3 support package')
    terminal.menu()
    for expected in ('READY TO SHARE', 'Secrets redacted', 'Private keys excluded', 'Keystores excluded', 'Final package rescanned', 'SHA-256 generated'):
        assert expected in terminal.display(), expected
    if variant == 'blocked':
        terminal.capture('24-execution-context-support.png', 'Sanitized support package with context proof')
    terminal.action('Back')
    terminal.menu()
    terminal.action('Exit')
    terminal.finish(1 if variant == 'compatible' else 2)
    if variant == 'blocked':
        terminal.capture('25-execution-context-exit.png', 'Clean exit and restored cursor')
    results[terminal.name].update(validate_export(variant, terminal.output))
    command = list(terminal.command)
    command[command.index('--output') + 1] = str(OUTPUT / (variant + '-non-tty'))
    process = subprocess.run([*command, '--json'], capture_output=True, timeout=90)
    assert process.returncode == (1 if variant == 'compatible' else 2)
    assert b'\x1b[' not in process.stdout and b'Choose an action' not in process.stdout
    assert json.loads(process.stdout)['status'] == results[terminal.name]['status']
    (TRANSCRIPTS / (terminal.name + '-non-tty.json')).write_bytes(process.stdout)
    (TRANSCRIPTS / (terminal.name + '-non-tty.stderr')).write_bytes(process.stderr)
    results[terminal.name + '-non-tty'] = {'exit': process.returncode, 'oneJsonDocument': True, 'noCursorControls': True}

(SHOTS / 'manifest-execution-context.json').write_text(json.dumps(manifest, indent=2) + '\n')
(ROOT / 'execution-context-terminal-validation.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
