"""Capture real packaged inherited-member CLI sessions in Ubuntu PTYs.

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
WORK = pathlib.Path('/work/hierarchy')
SHOTS = ROOT / 'screenshots'
TRANSCRIPTS = ROOT / 'terminal-transcripts'
OUTPUT = ROOT / 'hierarchy-artifacts'
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
    for forbidden in ('Compatibility analysis incomplete', 'PublicFacade', 'SourceHelpers', 'TargetHelpers'):
        assert forbidden not in text, forbidden


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class Terminal:
    def __init__(self, variant):
        self.variant = variant
        self.name = 'hierarchy-' + variant
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
        if variant == 'blocked-tvu':
            self.command += ['--tvu-results', str(self.base / 'tvu.log'), '--tvu-results', str(self.base / 'errors.zip')]
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
                if self.variant != 'blocked-tvu':
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


# Reuse the same strict exported-proof/package checks as the final cross-validator.
import importlib.util
spec = importlib.util.spec_from_file_location('hierarchy_checks', pathlib.Path(__file__).with_name('validate-hierarchy.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)

for variant in ('blocked-no-tvu', 'blocked-tvu', 'compatible'):
    source = ROOT / 'synthetic/hierarchy' / ('compatible' if variant == 'compatible' else 'blocked')
    destination = WORK / variant
    destination.mkdir()
    shutil.copytree(source / 'node', destination / 'ExampleIssuer')
    shutil.copytree(source / 'kit', destination / 'kit')
    for name in ('host.json', 'classpath.txt', 'tvu.log', 'errors.zip'):
        shutil.copyfile(source / name, destination / name)
    terminal = Terminal(variant)
    terminal.menu()
    terminal.record_heap()
    for expected in ('NODE DISCOVERED', 'ExampleIssuer', '4.11.6', 'Platform 13', '4.12.11', 'Platform 140', '1.8.0_242', 'PostgreSQL', '2 current', '2 target', 'TVU          Found', '> Continue'):
        assert expected in terminal.display(), (variant, expected)
    if variant == 'blocked-no-tvu':
        terminal.capture('29-hierarchy-environment.png', 'Unchanged Environment with generated hierarchy fixture')
    terminal.action('Continue')
    terminal.menu()
    if variant == 'compatible':
        assert 'READY FOR TVU' in terminal.display() and 'View compatibility evidence' not in terminal.display()
        terminal.capture('38-hierarchy-compatible.png', 'Compatible inherited helper without an incomplete finding')
    else:
        assert 'NOT READY TO UPGRADE' in terminal.display() and 'CorDapp compatibility' in terminal.display()
        if variant == 'blocked-tvu':
            for term in ('3 blockers', '650 processed', '449 passed', '201 failed', '201 supplied failures match'):
                assert term in terminal.display(), term
            terminal.capture('36-hierarchy-tvu-result.png', 'Correlated TVU failure with no inherited-helper noise')
        else:
            assert '1 blocker' in terminal.display() and 'View TVU evidence' not in terminal.display()
            terminal.capture('30-hierarchy-static-result.png', 'Static blocker with automatic guided schema preparation')
        terminal.action('View compatibility evidence')
        terminal.menu()
        for term in ('example-old-contract.jar', 'org.example.runtime.Amounts.total(Iterable)', 'Current runtime', 'Target runtime', 'Target verifier', 'Method found', 'Method missing'):
            assert term in terminal.display(), term
        assert 'example-new-contract.jar' not in terminal.display()
        if variant == 'blocked-no-tvu':
            terminal.capture('31-hierarchy-static-proof.png', 'Only the genuine missing-method compatibility proof')
        terminal.action('Back')
        terminal.menu()
        terminal.action('View schema evidence')
        terminal.menu()
        for term in ('SCHEMA EVIDENCE', 'Primary / effective schema', 'ExampleSchema', 'What LedgerPreflight found', 'Why this matters', 'Recommended action'):
            assert term in terminal.display(), term
        if variant == 'blocked-no-tvu':
            terminal.capture('32-hierarchy-schema.png', 'Frozen schema evidence')
        terminal.action('Back')
        terminal.menu()
        if variant == 'blocked-tvu':
            terminal.action('View TVU evidence')
            terminal.menu()
            for term in ('TVU EVIDENCE', '650', '449', '201', '201 supplied failures match'):
                assert term in terminal.display(), term
            terminal.capture('37-hierarchy-tvu-evidence.png', 'All supplied TVU failures correlate to the preserved blocker')
            terminal.action('Back')
            terminal.menu()
    terminal.action('Export full technical report')
    terminal.menu()
    assert 'Technical report exported' in terminal.display()
    if variant == 'blocked-no-tvu':
        terminal.capture('33-hierarchy-report-export.png', 'Full assessment with inherited declaring-class proof exported')
    terminal.action('Back')
    terminal.menu()
    terminal.action('Create R3 support package')
    terminal.menu()
    for term in ('READY TO SHARE', 'Secrets redacted', 'Private keys excluded', 'Keystores excluded', 'Final package rescanned', 'SHA-256 generated'):
        assert term in terminal.display(), term
    if variant == 'blocked-no-tvu':
        terminal.capture('34-hierarchy-r3-support.png', 'Sanitized package includes exact hierarchy and context proof')
    terminal.action('Back')
    terminal.menu()
    terminal.action('Exit')
    terminal.finish(1 if variant == 'compatible' else 2)
    if variant == 'blocked-no-tvu':
        terminal.capture('35-hierarchy-exit.png', 'Clean terminal exit')
    results[terminal.name]['supportPackage'] = checks.validate_export(terminal.output, variant)
    results[terminal.name]['inheritedHelperCompatible'] = True
    command = list(terminal.command)
    command[command.index('--output') + 1] = str(OUTPUT / (variant + '-non-tty'))
    process = subprocess.run([*command, '--json'], capture_output=True, timeout=90)
    assert process.returncode == (1 if variant == 'compatible' else 2)
    assert b'\x1b[' not in process.stdout and b'Choose an action' not in process.stdout
    checks.report_proof(json.loads(process.stdout), variant)
    (TRANSCRIPTS / (terminal.name + '-non-tty.json')).write_bytes(process.stdout)
    (TRANSCRIPTS / (terminal.name + '-non-tty.stderr')).write_bytes(process.stderr)
    results[terminal.name + '-non-tty'] = {'exit': process.returncode, 'oneJsonDocument': True, 'noCursorControls': True}

(SHOTS / 'manifest-hierarchy.json').write_text(json.dumps(manifest, indent=2) + '\n')
(ROOT / 'hierarchy-terminal-validation.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
