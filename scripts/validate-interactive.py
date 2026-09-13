"""Execute the packaged CLI in real Ubuntu PTYs; render only the emulator cell buffer.
No HTML, reconstructed CLI text or screenshot text edits are used.
"""
import re, os, pty, select, time, termios, fcntl, struct, json, pathlib, subprocess, codecs, shutil, hashlib
import pyte
from PIL import Image, ImageDraw, ImageFont
JAR=os.environ.get('LP_TEST_JAR','/dist/ledger-preflight-0.1.0.jar')
LAUNCH=[os.environ['LP_TEST_LAUNCHER']] if os.environ.get('LP_TEST_LAUNCHER') else ['java','-Xmx256m','-jar',JAR]
ROOT=pathlib.Path('/dist');SHOTS=ROOT/'screenshots';SHOTS.mkdir(exist_ok=True)
TRANS=ROOT/'terminal-transcripts';TRANS.mkdir(exist_ok=True)
results={};manifest=[]
FONT=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',18)
for kind in ('environment','blocked','clean'):
    source=ROOT/'synthetic/product-acceptance'/kind
    destination=pathlib.Path('/work')/kind
    shutil.copytree(source,destination)
    (destination/'current-node').rename(destination/'ExampleIssuer')
    expected=json.loads((ROOT/'synthetic/product-acceptance'/(kind+'-asserted')/'report.json').read_text())
    identity=expected['evidence']['discovery'];schema=expected['evidence']['schema-analysis']['safeSettings']
    assert (identity['sourcePlatform'],identity['targetPlatform'],identity['confidence'])==('13','140','HIGH')
    assert (identity['currentCordappJars'],identity['targetCordappJars'])==(2,2)
    assert expected['sourceVersion']=='4.11.6' and expected['targetVersion']=='4.12.11'
    assert schema['databaseVendor']=='PostgreSQL'
    if kind=='environment':assert schema['schemas']==['ExampleMixedCaseIssuer','shared_reference']
class Terminal:
    def __init__(self,name,kind='blocked',args=(),cols=92,rows=52,env=None,node=None,kit=None,guided=False,output=None):
        self.name=name;self.cols=cols;self.rows=rows;self.data=bytearray();self.decoder=codecs.getincrementaldecoder('utf8')('replace')
        self.screen=pyte.Screen(cols,rows);self.stream=pyte.Stream(self.screen)
        base='/work/'+kind
        extras=['--host-environment',base+'/host.json','--network-mode','all-4.12']
        if kind=='blocked':extras+=['--tvu-results',base+'/tvu.log','--tvu-results',base+'/errors.zip','--verifier-classpath',base+'/classpath.txt']
        self.pid,self.fd=pty.fork()
        if self.pid==0:
            os.environ['TERM']='xterm-256color';os.environ.pop('CI',None)
            if env:os.environ.update(env)
            os.execvp(LAUNCH[0],LAUNCH if guided else [*LAUNCH,'assess','--node',node or base+'/ExampleIssuer','--upgrade-kit',kit or base+'/upgrade-kit','--output',output or '/work/reports/'+name,*extras,*args])
        fcntl.ioctl(self.fd,termios.TIOCSWINSZ,struct.pack('HHHH',rows,cols,0,0))
    def read(self,timeout=.1):
        if select.select([self.fd],[],[],timeout)[0]:
            try:chunk=os.read(self.fd,65536)
            except OSError:return False
            if not chunk:return False
            self.data.extend(chunk);self.stream.feed(self.decoder.decode(chunk));return True
        return False
    def until(self,expected,timeout=35):
        start=len(self.data);end=time.monotonic()+timeout
        while time.monotonic()<end:
            if expected.encode() in self.data[start:]:
                while self.read(.15):pass
                return
            self.read(.15)
        raise AssertionError('Missing '+expected+' in '+self.name+'\n'+self.data.decode(errors='replace')[-2500:])
    def menu(self):
        self.until('Up/Down');assert '> ' in '\n'.join(self.screen.display)
        assert not any(g in '\n'.join(self.screen.display) for g in ('❯','□','■','▶'))
        assert b'\x1b[?25l' in self.data and self.screen.cursor.hidden
    def choose(self,n):
        if n>1:
            os.write(self.fd,b'\x1b[B'*(n-1));self.until('Up/Down')
        os.write(self.fd,b'\r')
    def shot(self,name):
        lines=self.screen.display
        for bad in ('REQUIRED_OR_UNRESOLVED','Analyzer:','C:\\Users','SyntheticPasswordOnly42','UNVERIFIED'):
            assert bad not in '\n'.join(lines),bad
        bottom=max((i for i,line in enumerate(lines) if line.strip()),default=0)+2
        image=Image.new('RGB',(self.cols*11+40,bottom*27+32),(31,24,36));draw=ImageDraw.Draw(image)
        for row,line in enumerate(lines[:bottom]):draw.text((20,16+row*27),line,font=FONT,fill=(245,241,247))
        path=SHOTS/name;image.save(path)
        (SHOTS/(name+'.txt')).write_text('\n'.join(lines[:bottom])+'\n')
        manifest.append({'file':name,'source':'actual Ubuntu 22.04 PTY emulator cell buffer','columns':self.cols,'rows':self.rows,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    def finish(self,expected):
        end=time.monotonic()+45
        while time.monotonic()<end:
            self.read(.1);done,status=os.waitpid(self.pid,os.WNOHANG)
            if done:
                while self.read(.05):pass
                attrs=termios.tcgetattr(self.fd)
                assert attrs[3]&termios.ECHO and attrs[3]&termios.ICANON
                code=os.waitstatus_to_exitcode(status);assert code==expected,(self.name,code,expected)
                (TRANS/(self.name+'.ansi')).write_bytes(self.data)
                hidden=b'\x1b[?25l' in self.data
                if hidden:assert self.data.rfind(b'\x1b[?25h')>self.data.rfind(b'\x1b[?25l') and not self.screen.cursor.hidden
                results[self.name]={'exit':code,'terminalRestored':True,'cursorHiddenDuringMenu':hidden,'cursorRestored':not self.screen.cursor.hidden};return
        os.kill(self.pid,9);raise AssertionError('Session failed to exit: '+self.name+'\n'+self.data.decode(errors='replace')[-2500:])

def display(t):return '\n'.join(t.screen.display)
def no_internal(t):
    for text in ('Other JARs','Discovery confidence','REQUIRED_OR_UNRESOLVED','Analyzer:','JVM descriptor','legacy-jars/','sha256','PARTIAL','MEDIUM','HIGH','Understand the blockers'):
        assert text not in display(t),text
t=Terminal('environment','environment');t.menu()
for expected in ('NODE DISCOVERED','ExampleIssuer','4.11.6','Platform 13','4.12.11','Platform 140','1.8.0_242','Schemas      2 detected','Primary      ExampleMixedCaseIssuer','2 current','2 target','TVU          Found','> Continue'):
    assert expected in display(t),expected
no_internal(t);t.shot('01-environment-discovered.png');t.choose(2);t.finish(0)

t=Terminal('blocked');t.menu();t.choose(1);t.menu();no_internal(t)
for term in ('NOT READY TO UPGRADE','WHAT HAPPENED','WHY IT MATTERS','WHAT TO DO','NEXT STEP','201 supplied failures match','449 passed','2 issues need attention','Create R3 support package'):
    assert term in display(t),term
t.shot('02-blocked-result.png')
t.choose(1);t.menu();t.shot('05-technical-evidence.png');t.choose(6);t.menu()
assert 'Assessment generated' in display(t);t.shot('06-technical-assessment-created.png')
t.choose(1);t.menu();t.choose(8);t.menu();t.choose(2);t.menu()
assert 'READY TO SHARE' in display(t) and 'Final package rescanned' in display(t)
t.shot('07-r3-support-ready.png');t.choose(1);t.menu();t.choose(4);t.finish(2);t.shot('08-clean-exit.png')

t=Terminal('ready-for-tvu','clean');t.menu();t.choose(1);t.menu();no_internal(t)
assert 'READY FOR TVU' in display(t) and 'TVU instructions' in display(t)
t.shot('03-ready-for-tvu.png');t.choose(1);t.menu();t.shot('09-tvu-instructions.png')
t.choose(1);t.until('TVU log, error ZIP');os.write(t.fd,b'/work/clean/tvu.log\n');t.menu();t.choose(1);t.menu();t.choose(1);t.menu()
assert 'READY TO UPGRADE' in display(t) and 'View upgrade checklist' in display(t)
t.choose(1);t.menu();t.shot('10-upgrade-checklist.png');t.choose(1);t.menu();t.choose(3);t.finish(0)

t=Terminal('ready-to-upgrade','clean',['--tvu-results','/work/clean/tvu.log']);t.menu();t.choose(1);t.menu()
assert 'READY TO UPGRADE' in display(t);no_internal(t);t.shot('04-ready-to-upgrade.png');t.choose(3);t.finish(0)
for name,key,code in [('q',b'q',2),('ctrl-c',b'\x03',130)]:
    t=Terminal(name);t.menu();t.choose(1);t.menu();os.write(t.fd,key);t.finish(code)
t=Terminal('sigterm');t.menu();os.kill(t.pid,15);t.finish(143)
t=Terminal('unexpected-output-failure','clean',output='/proc/ledgerpreflight-unwritable');t.menu();t.choose(1);t.finish(3)
assert b'Assessment error' in t.data
t=Terminal('run-again');t.menu();t.choose(1);t.menu();t.choose(3);t.menu()
assert 'NOT READY TO UPGRADE' in display(t);t.choose(4);t.finish(2)

t=Terminal('plain','clean',['--plain-terminal']);t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');os.write(t.fd,b'3\n');t.finish(1);assert b'\x1b[' not in t.data
t=Terminal('narrow','clean',['--plain-terminal'],cols=40,rows=52);t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');t.shot('11-narrow-terminal.png');os.write(t.fd,b'3\n');t.finish(1)
t=Terminal('ssh-arrows','clean',cols=36,rows=52,env={'SSH_TTY':'/dev/pts/1','LANG':'C.UTF-8'});t.menu()
os.write(t.fd,b'\x1b[B');t.until('Up/Down');assert '> Exit' in display(t)
os.write(t.fd,b'\x1b[A');t.until('Up/Down');assert '> Continue' in display(t);os.write(t.fd,b'q');t.finish(0)
for name,args,env in [('ci',[],{'CI':'true'}),('noninteractive',['--non-interactive'],None),('json',['--json'],None)]:
    t=Terminal(name,'clean',args,env=env);t.finish(1);assert b'\x1b[' not in re.sub(rb'\x1b\[[0-9;]*m',b'',t.data)
    if name!='noninteractive':assert b'\x1b[' not in t.data
p=subprocess.run([*LAUNCH,'assess','--node','/work/clean/ExampleIssuer','--upgrade-kit','/work/clean/upgrade-kit','--host-environment','/work/clean/host.json','--output','/work/reports/piped','--json'],capture_output=True,timeout=45)
assert p.returncode==1 and json.loads(p.stdout)['status']=='READY FOR TVU' and b'\x1b[' not in p.stdout
results['piped-json']={'exit':1,'oneJsonDocument':True,'noCursorControls':True}
# Content-driven disambiguation remains before the two-option environment gate.
company=pathlib.Path('/work/nodes');company.mkdir()
shutil.copytree('/work/clean/ExampleIssuer',company/'Issuer');shutil.copytree('/work/clean/ExampleIssuer',company/'Notary')
with (company/'Notary/node.conf').open('a') as conf:conf.write('\nnotary.validating=false\n')
t=Terminal('node-selection','clean',node=str(company));t.menu();assert 'Non-validating notary' in display(t);t.choose(2);t.menu();assert 'Non-validating notary' in display(t);t.choose(2);t.finish(0)
kit=pathlib.Path('/work/ambiguous-kit');shutil.copytree('/work/clean/upgrade-kit',kit)
shutil.copyfile(kit/'renamed-runtime.bin',kit/'alternate-runtime.jar');shutil.copyfile(kit/'renamed-validator.jar',kit/'alternate-tool.jar')
t=Terminal('artifact-selection','clean',kit=str(kit));t.menu();t.choose(1);t.menu();t.choose(1);t.menu();t.choose(2);t.finish(0)
t=Terminal('guided-start','clean',guided=True);t.until('Current node directory:');os.write(t.fd,b'/work/clean/ExampleIssuer\n');t.until('Target upgrade-kit directory:');os.write(t.fd,b'/work/clean/upgrade-kit\n');t.menu();t.choose(2);t.finish(0)
t=Terminal('guided-cancel','clean',guided=True);t.until('Current node directory:');os.write(t.fd,b'\n');t.finish(0)
# Explicit TVU cancellation still launches no process and produces no captures.
clone=pathlib.Path('/work/isolated-copy');shutil.copytree('/work/clean/ExampleIssuer',clone)
conf=clone/'node.conf';conf.write_text(conf.read_text().replace('database.example/example','disposable.example/validation'))
shutil.rmtree(clone/'cordapps');shutil.copytree('/work/clean/upgrade-kit/cordapps',clone/'cordapps')
t=Terminal('tvu-execution-cancel','clean');t.menu();t.choose(1);t.menu();t.choose(1);t.menu();t.choose(2);t.until('Prepared isolated validation-copy directory');os.write(t.fd,str(clone).encode()+b'\n')
t.until('Confirmation');os.write(t.fd,b'NO\n');t.menu();assert b'TVU execution cancelled' in t.data;t.choose(1);t.menu();t.choose(3);t.finish(1)
assert not list(pathlib.Path('/work/reports/tvu-execution-cancel').glob('tvu-run-*'))
# The asserted real-structure fixture must also traverse Continue using the shipped launcher.
for kind,fixture in [('run-a','normal'),('run-a-limited','large')]:
    destination=pathlib.Path('/work')/kind
    shutil.copytree(ROOT/'synthetic/run-a'/fixture,destination)
    (destination/'current-node').rename(destination/'ExampleIssuer')
    t=Terminal(kind,kind,args=['--verifier-classpath',str(destination/'classpath.txt')],rows=60)
    t.menu()
    for expected in ('4.11.6','Platform 13','4.12.11','Platform 140','ExampleSchema','CorDapps','2 current','2 target','TVU          Found'):
        assert expected in display(t),expected
    no_internal(t)
    if kind=='run-a':
        manifest[:]=[m for m in manifest if m['file']!='01-environment-discovered.png']
        t.shot('01-environment-discovered.png')
    t.choose(1);t.menu()
    assert 'NOT READY TO UPGRADE' in display(t)
    if kind=='run-a':assert 'CorDapp compatibility' in display(t);t.shot('12-run-a-continue-result.png')
    else:assert 'Compatibility analysis incomplete' in display(t);t.shot('13-graceful-incomplete-result.png')
    t.choose(4);t.finish(2)
    assert b'OutOfMemoryError' not in t.data
shutil.copytree('/work/reports',ROOT/'interactive-artifacts')
(SHOTS/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(ROOT/'interactive-validation.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
