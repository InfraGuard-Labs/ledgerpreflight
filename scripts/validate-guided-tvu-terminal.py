"""Capture the actual shipped CLI and executable synthetic TVU in Ubuntu PTYs.

All PNG characters come directly from the terminal emulator cell buffer. Full
unmodified ANSI streams and cell text accompany the images. No mock output.
"""
import codecs
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import pty
import select
import shutil
import signal
import struct
import subprocess
import termios
import time

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path('/dist')
WORK = pathlib.Path('/work/guided-tvu')
OUTPUT = ROOT / 'guided-tvu-artifacts'
SHOTS = ROOT / 'screenshots'
TRANSCRIPTS = ROOT / 'terminal-transcripts'
LAUNCHER = os.environ.get('LP_TEST_LAUNCHER', '/tmp/lp/ledger-preflight-0.1.0/ledger-preflight')
assert pathlib.Path(LAUNCHER).is_file()
assert 'ID=ubuntu' in pathlib.Path('/etc/os-release').read_text()
assert os.uname().machine == 'x86_64'
for directory in (WORK, OUTPUT, SHOTS, TRANSCRIPTS):
    directory.mkdir(parents=True, exist_ok=True)
FONT = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 18)
manifest, results = [], {}
spec = importlib.util.spec_from_file_location('guided_checks', pathlib.Path(__file__).with_name('validate-guided-tvu.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def quiet(text):
    for forbidden in ('SyntheticGuidedCredential42', 'C:\\Users', 'LP-API', 'LP-DB', 'LP-ANALYSIS',
                      'Ljava/', 'External verifier process started', 'unable to verify with external verifier',
                      'Exception in thread', 'OutOfMemoryError', 'REQUIRED_OR_UNRESOLVED',
                      'TARGET_NODE_RUNTIME', 'TARGET_VERIFIER', 'currentInventory', '--tvu-results'):
        assert forbidden not in text, forbidden


class Terminal:
    def __init__(self, name, mode):
        self.name, self.mode = name, mode
        self.base, self.output, self.control = WORK / name, OUTPUT / name, WORK / name / 'observations'
        source = ROOT / 'synthetic/guided-tvu' / mode
        shutil.copytree(source, self.base)
        self.control.mkdir()
        # Exported fixtures remain original; only disposable input copy modes change.
        for directory in (self.base / 'node', self.base / 'kit'):
            for path in directory.rglob('*'):
                path.chmod(0o555 if path.is_dir() else 0o444)
            directory.chmod(0o555)
        self.before = checks.input_hashes(self.base)
        self.cols, self.rows = 100, 60
        self.data = bytearray()
        self.screen = pyte.Screen(self.cols, self.rows)
        self.stream = pyte.Stream(self.screen)
        self.decoder = codecs.getincrementaldecoder('utf8')('replace')
        self.command = [LAUNCHER, 'assess', '--node', str(self.base / 'node'), '--upgrade-kit', str(self.base / 'kit'),
                        '--host-environment', str(self.base / 'host.json'), '--verifier-classpath', str(self.base / 'classpath.txt'),
                        '--network-mode', 'all-4.12', '--output', str(self.output)]
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ.update(TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8',
                              SYNTHETIC_TVU_CONTROL=str(self.control), SYNTHETIC_TVU_DELAY_MS='1800')
            os.environ.pop('CI', None)
            os.execvp(self.command[0], self.command)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', self.rows, self.cols, 0, 0))
        self.mark = 0

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

    def until(self, text, timeout=120, drain=True):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text.encode() in self.data[self.mark:]:
                if drain:
                    while self.read(.08):
                        pass
                return
            self.read(.1)
        raise AssertionError((self.name, text, self.data.decode(errors='replace')[-5000:]))

    def send(self, data):
        self.mark = len(self.data)
        os.write(self.fd, data)

    def frame(self, *texts, timeout=120):
        # PTY reads can split a redraw after the counter but before Status/menu.
        # Wait for the complete observed frame, not only an earlier byte token.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.display()
            if all(text in current for text in texts):
                return
            self.read(.1)
        (TRANSCRIPTS / ('guided-tvu-' + self.name + '-incomplete-frame.ansi')).write_bytes(self.data)
        (TRANSCRIPTS / ('guided-tvu-' + self.name + '-incomplete-frame.txt')).write_text(self.display())
        raise AssertionError((self.name, 'Complete progress frame not observed', texts, self.display()))

    def menu(self):
        self.until('Up/Down')
        quiet(self.display())
        assert self.screen.cursor.hidden

    def display(self):
        return '\n'.join(self.screen.display)

    def action(self, label):
        lines = list(self.screen.display)
        first = max(index for index, line in enumerate(lines) if line.startswith('> '))
        labels = []
        for line in lines[first:]:
            if 'Up/Down' in line:
                break
            labels.append(line[2:].strip())
        assert label in labels, (self.name, label, labels)
        count = labels.index(label)
        if count:
            self.send(b'\x1b[B' * count)
            self.until('Up/Down')
        self.send(b'\r')

    def capture(self, filename, label):
        lines = list(self.screen.display)
        quiet('\n'.join(lines))
        bottom = max((i for i, line in enumerate(lines) if line.strip()), default=0) + 2
        image = Image.new('RGB', (self.cols * 11 + 40, bottom * 27 + 32), (31, 24, 36))
        draw = ImageDraw.Draw(image)
        for row, line in enumerate(lines[:bottom]):
            draw.text((20, 16 + row * 27), line, font=FONT, fill=(245, 241, 247))
        path = SHOTS / filename
        image.save(path)
        path.with_name(path.name + '.txt').write_text('\n'.join(lines[:bottom]) + '\n')
        manifest.append({'file': filename, 'label': label, 'session': self.name,
                         'source': 'actual Ubuntu PTY emulator cell buffer from the packaged launcher',
                         'columns': self.cols, 'rows': self.rows, 'sha256': checks.sha(path)})

    def start(self):
        self.menu()
        for text in ('NODE DISCOVERED', '4.11.6', '4.12.11', '1.8.0_242', 'PostgreSQL', 'ExampleSchema', '> Continue'):
            assert text in self.display(), text
        command = pathlib.Path(f'/proc/{self.pid}/cmdline').read_bytes().split(b'\0')
        assert [value for value in command if value.startswith(b'-Xmx')] == [b'-Xmx256m']
        (TRANSCRIPTS / ('guided-tvu-' + self.name + '.command.txt')).write_bytes(b'\n'.join(command))
        assert not (self.control / 'started.pid').exists()
        if self.name == 'failed':
            self.capture('50-guided-tvu-environment.png', 'Unchanged discovered source and target environment')
        self.action('Continue')
        self.menu()

    def finish(self, expected):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            self.read(.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self.read(.05):
                    pass
                code = os.waitstatus_to_exitcode(status)
                assert code == expected, (self.name, code, expected)
                modes = termios.tcgetattr(self.fd)
                assert modes[3] & termios.ECHO and modes[3] & termios.ICANON
                assert self.data.rfind(b'\x1b[?25h') > self.data.rfind(b'\x1b[?25l')
                assert not self.screen.cursor.hidden
                assert 'Session complete' in self.display()
                quiet(self.data.decode(errors='replace'))
                assert checks.input_hashes(self.base) == self.before
                assert not list(self.output.rglob('.workspace-*'))
                for path in self.control.glob('*.pid'):
                    assert not pathlib.Path('/proc', path.read_text().strip()).exists(), path.name
                (TRANSCRIPTS / ('guided-tvu-' + self.name + '.ansi')).write_bytes(self.data)
                os.close(self.fd)
                results[self.name] = {'exit': code, 'heap': '-Xmx256m', 'terminalRestored': True,
                                      'inputsUnchanged': True, 'noOrphanProcesses': True, 'workspaceCleaned': True}
                return
        os.kill(self.pid, signal.SIGKILL)
        raise AssertionError('Session did not exit: ' + self.name)


def back(terminal):
    terminal.action('Back')
    terminal.menu()


def export_support(terminal, pictures=False):
    terminal.action('Export full technical report')
    terminal.menu()
    assert 'Technical report exported' in terminal.display()
    if pictures:
        terminal.capture('59-guided-tvu-report.png', 'Automatically reassessed HTML, JSON and text report exported')
    back(terminal)
    terminal.action('Create R3 support package')
    terminal.menu()
    assert 'READY TO SHARE' in terminal.display() and 'Final package rescanned' in terminal.display()
    if pictures:
        terminal.capture('60-guided-tvu-support.png', 'Sanitized support package with guided run evidence and SHA-256')
    back(terminal)


failed = Terminal('failed', 'failed')
failed.start()
assert '1 blocker' in failed.display() and 'Schema setup' in failed.display()
failed.capture('51-guided-tvu-static-result.png', 'Initial compatibility blocker and automatically prepared schema workflow')
failed.action('Run TVU safely')
failed.menu()
for value in ('RUN TVU SAFELY', 'Exact execution command', 'isolated / non-production', 'Yes, run TVU'):
    assert value in failed.display(), value
failed.capture('52-guided-tvu-database-confirmation.png', 'Explicit isolated database confirmation before any process or workspace')
failed.action('Cancel')
failed.menu()
assert not (failed.control / 'started.pid').exists()
assert not (failed.output / 'tvu').exists()
results['refusedInteractive'] = {'noProcess': True, 'noWorkspace': True}
failed.action('Run TVU safely')
failed.menu()
failed.action('Use a different safe node configuration')
failed.until('Safe node configuration path')
alternate = failed.base / 'safe-copy.conf'
alternate.write_text((failed.base / 'node/node.conf').read_text().replace('isolated_copy', 'alternate_copy'))
failed.send(str(alternate).encode() + b'\n')
failed.menu()
assert 'alternate_copy' in failed.display()
failed.capture('53-guided-tvu-alternate-configuration.png', 'Alternate isolated database configuration requires fresh confirmation')
failed.action('Yes, run TVU')
failed.frame('650 / 650', 'Status', 'In progress', '> Cancel TVU', 'Enter or q cancels.')
assert 'Status' in failed.display() and 'In progress' in failed.display()
failed.capture('54-guided-tvu-progress.png', 'Observed transaction counters during actual synthetic TVU execution')
failed.menu()
for value in ('2 blockers', '650 processed', '449 passed', '201 failed', '201 supplied failures match', 'Schema setup'):
    assert value in failed.display(), value
failed.capture('55-guided-tvu-failed-result.png', 'Failed TVU automatically analyzed with all 201 failures correlated')
for action, number, slug, required in (
        ('View compatibility evidence', 56, 'compatibility', 'COMPATIBILITY EVIDENCE'),
        ('View TVU evidence', 57, 'evidence', 'TVU EVIDENCE'),
        ('View schema evidence', 58, 'schema-handled', 'SCHEMA EVIDENCE')):
    failed.action(action)
    failed.menu()
    assert required in failed.display()
    failed.capture(f'{number}-guided-tvu-{slug}.png', action + ' after the guided run')
    back(failed)
export_support(failed, True)
failed.action('Run TVU again')
failed.menu()
failed.capture('61-guided-tvu-rerun.png', 'Another TVU run requires another isolated database confirmation')
failed.action('Yes, run TVU')
failed.menu()
assert len(list((failed.output / 'tvu').glob('*/run-manifest.json'))) == 2
failed.action('Exit')
failed.finish(2)
failed.capture('66-guided-tvu-exit.png', 'Clean session exit with restored terminal and captured assessment')
results['failed']['supportPackage'] = checks.validate_session(failed.output, 'failed')

success = Terminal('success', 'success')
success.start()
assert 'READY FOR TVU' in success.display()
success.capture('62-guided-tvu-ready-for-tvu.png', 'Compatible artifacts wait for actual historical validation')
success.action('Run TVU safely')
success.menu()
success.action('Yes, run TVU')
success.menu()
assert 'READY TO UPGRADE' in success.display()
success.capture('63-guided-tvu-ready-to-upgrade.png', 'Actual complete TVU success and static proof permit upgrade readiness')
export_support(success)
success.action('Exit')
success.finish(0)
results['success']['supportPackage'] = checks.validate_session(success.output, 'success')

imported = Terminal('imported', 'failed')
imported.start()
run = sorted((failed.output / 'tvu').glob('*/run-manifest.json'))[0]
evidence = [run.parent / name for name in json.loads(run.read_text())['evidence']]
assert any(path.suffix == '.zip' for path in evidence)
imported.action('Import existing TVU results')
imported.until('TVU log, error ZIP or directory')
imported.send(str(evidence[0]).encode() + b'\n')
imported.menu()
for path in evidence[1:]:
    imported.action('Add another file from the same run')
    imported.until('Additional evidence path')
    imported.send(str(path).encode() + b'\n')
    imported.menu()
imported.action('Analyze this run')
imported.menu()
assert '201 supplied failures match' in imported.display()
assert '2 blockers' in imported.display()
assert not (imported.control / 'started.pid').exists()
imported.capture('64-guided-tvu-imported-result.png', 'Existing complete evidence imported and analyzed without executing TVU')
export_support(imported)
imported.action('Exit')
imported.finish(2)
results['imported']['supportPackage'] = checks.validate_session(imported.output, 'imported')

cancel = Terminal('cancel', 'cancel')
cancel.start()
cancel.action('Run TVU safely')
cancel.menu()
cancel.action('Yes, run TVU')
cancel.until('Cancel TVU', drain=False)
deadline = time.monotonic() + 30
while not (cancel.control / 'grandchild.pid').exists() and time.monotonic() < deadline:
    cancel.read(.1)
assert (cancel.control / 'grandchild.pid').exists()
cancel.send(b'q')
cancel.menu()
assert 'cancelled' in cancel.display().lower()
assert 'NOT READY TO UPGRADE' in cancel.display()
assert not any(line.strip() == '✓ READY TO UPGRADE' for line in cancel.screen.display)
assert 'TVU verification failure' not in cancel.display()
assert 'Resolve supplied root causes' not in cancel.display()
assert 'Run TVU again when ready to complete validation.' in cancel.display()
cancel.capture('65-guided-tvu-cancelled.png', 'Cancelled run saves partial evidence and stops validator descendants')
cancel.action('Exit')
cancel.finish(2)
results['cancel']['partialEvidenceRetained'] = bool(list(cancel.output.rglob('tvu-run.json')))

refused = subprocess.run([LAUNCHER, 'assess', '--node', '/missing-node', '--upgrade-kit', '/missing-kit', '--run-tvu', '--json'], capture_output=True, timeout=30)
assert refused.returncode == 3 and b'--confirm-isolated-db' in refused.stderr and not refused.stdout
(TRANSCRIPTS / 'guided-tvu-noninteractive-refusal.stderr').write_bytes(refused.stderr)
results['refusedNoninteractive'] = {'exit': refused.returncode, 'noInputRead': True, 'noProcess': True}
assert len(manifest) == 17
(SHOTS / 'manifest-guided-tvu.json').write_text(json.dumps(manifest, indent=2) + '\n')
(ROOT / 'guided-tvu-terminal-validation.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
