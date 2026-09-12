"""Execute the packaged CLI in real Ubuntu PTYs; render only the emulator cell buffer.
No HTML, reconstructed CLI text or screenshot text edits are used.
"""
import os, pty, select, time, termios, fcntl, struct, json, pathlib, subprocess, codecs, shutil, hashlib
import pyte
from PIL import Image, ImageDraw, ImageFont
JAR=os.environ.get('LP_TEST_JAR','/dist/ledger-preflight-0.1.0.jar')
ROOT=pathlib.Path('/dist');SHOTS=ROOT/'screenshots';SHOTS.mkdir(exist_ok=True)
TRANS=ROOT/'terminal-transcripts';TRANS.mkdir(exist_ok=True)
results={};manifest=[]
FONT=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',18)
for kind in ('replay','clean'):
    source=pathlib.Path('/dist/synthetic')/kind
    destination=pathlib.Path('/work')/kind
    shutil.copytree(source,destination)
    (destination/'current-node').rename(destination/'ExampleIssuer')

class Terminal:
    def __init__(self,name,kind='replay',args=(),cols=92,rows=52,env=None,node=None,kit=None,guided=False):
        self.name=name;self.cols=cols;self.rows=rows;self.data=bytearray();self.decoder=codecs.getincrementaldecoder('utf8')('replace')
        self.screen=pyte.Screen(cols,rows);self.stream=pyte.Stream(self.screen)
        base='/work/'+kind
        extras=[]
        if kind=='replay':extras=['--tvu-results',base+'/tvu.log','--tvu-results',base+'/errors.zip','--verifier-classpath',base+'/classpath.txt']
        self.pid,self.fd=pty.fork()
        if self.pid==0:
            os.environ['TERM']='xterm-256color';os.environ.pop('CI',None)
            if env:os.environ.update(env)
            os.execvp('java',['java','-jar',JAR] if guided else ['java','-jar',JAR,'assess','--node',node or base+'/ExampleIssuer','--upgrade-kit',kit or base+'/upgrade-kit','--output','/work/reports/'+name,*extras,*args])
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
    def menu(self):self.until('↑/↓ select')
    def choose(self,n):
        if n>1:
            os.write(self.fd,b'\x1b[B'*(n-1));self.until('↑/↓ select')
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
                results[self.name]={'exit':code,'terminalRestored':True};return
        os.kill(self.pid,9);raise AssertionError('Session failed to exit: '+self.name+'\n'+self.data.decode(errors='replace')[-2500:])

t=Terminal('guided-start','clean',guided=True);t.until('Current node directory:');os.write(t.fd,b'/work/clean/ExampleIssuer\n');t.until('Target upgrade-kit directory:');os.write(t.fd,b'/work/clean/upgrade-kit\n');t.menu();t.choose(1);t.menu();t.choose(6);t.finish(1)
t=Terminal('guided-cancel','clean',guided=True);t.until('Current node directory:');os.write(t.fd,b'\n');t.finish(0)
t=Terminal('guided-ci','clean',guided=True,env={'CI':'true'});t.finish(0);assert b'Current node directory:' not in t.data
s=Terminal('blocked');s.menu();s.shot('17-discovery-summary.png');assert 'NODE DISCOVERED' in '\n'.join(s.screen.display)
s.choose(2);s.menu();s.shot('18-discovery-details.png');s.choose(1);s.menu();s.choose(1);s.menu();s.shot('01-blocked-main.png')
assert 'Understand the blockers' in '\n'.join(s.screen.display)
assert 'Showing 2 of' in '\n'.join(s.screen.display) and 'additional warnings' in '\n'.join(s.screen.display)
s.choose(1);s.menu();s.shot('04-understand-blockers-menu.png')
s.choose(1);s.menu();s.shot('05-blocker-explanation.png')
for heading in ('WHAT LEDGERPREFLIGHT FOUND','WHAT CHANGED','WHY THIS FAILS','IMPACT','EVIDENCE','RECOMMENDED NEXT ACTION'):assert heading in '\n'.join(s.screen.display)
s.choose(1);s.menu();s.shot('12-technical-evidence.png')
assert 'TECHNICAL EVIDENCE' in '\n'.join(s.screen.display) and 'View raw JSON' in '\n'.join(s.screen.display)
s.choose(1);s.menu() # human evidence -> explanation
s.choose(4);s.menu() # understand submenu
s.choose(3);s.menu();s.shot('13-resolution-plan.png')
s.choose(1);s.menu();s.choose(5);s.menu()
s.choose(2);s.menu();s.shot('06-tvu-validation-menu.png')
s.choose(1);s.menu();s.shot('07-tvu-readiness.png')
s.choose(1);s.menu();s.choose(2);s.menu();s.shot('14-tvu-preparation.png')
s.choose(1);s.menu();s.choose(5);s.menu()
s.choose(3);s.menu();s.shot('08-reports-support-menu.png')
s.choose(1);s.menu();s.shot('09-technical-report-created.png')
s.choose(1);s.menu();s.choose(2);s.menu();s.shot('10-r3-support-ready.png')
assert 'READY TO SHARE' in '\n'.join(s.screen.display)
assert 'ExampleIssuer-R3-support-' in '\n'.join(s.screen.display) and 'Final package rescanned' in '\n'.join(s.screen.display)
s.choose(1);s.menu();s.choose(3);s.menu();s.shot('15-generated-artifacts.png')
s.choose(1);s.menu();s.choose(4);s.menu();s.choose(4);s.finish(2);s.shot('11-exit.png')
for name,args,shot,code in [('static',[],'02-ready-for-tvu-main.png',1),('ready',['--tvu-results','/work/clean/tvu.log'],'03-ready-to-upgrade-main.png',0)]:
    t=Terminal(name,'clean',args);t.menu();t.choose(1);t.menu();t.shot(shot);assert 'Understand the blockers' not in '\n'.join(t.screen.display);t.choose(6 if name=='static' else 4);t.finish(code)
for name,keys in [('ctrl-d',b'\x04'),('ctrl-c',b'\x03')]:
    t=Terminal(name);t.menu();t.choose(1);t.menu();os.write(t.fd,keys);t.finish(130 if name=='ctrl-c' else 2)
t=Terminal('plain','clean',['--plain-terminal']);t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');os.write(t.fd,b'6\n');t.finish(1);assert b'\x1b[' not in t.data
# A narrow plain terminal displays full wrapped labels rather than hiding the action name.
t=Terminal('narrow','clean',['--plain-terminal'],cols=40,rows=52);t.until('Choose an action');os.write(t.fd,b'1\n');t.until('Choose an action');t.shot('16-narrow-terminal.png');os.write(t.fd,b'6\n');t.finish(1)
for name,args,env in [('ci',[],{'CI':'true'}),('noninteractive',['--non-interactive'],None),('json',['--json'],None)]:
    t=Terminal(name,'clean',args,env=env);t.finish(1);assert b'WHAT WOULD YOU LIKE' not in t.data
proc=subprocess.run(['java','-jar',JAR,'assess','--node','/work/clean/ExampleIssuer','--upgrade-kit','/work/clean/upgrade-kit','--output','/work/reports/piped','--json'],capture_output=True,timeout=30)
assert proc.returncode==1 and json.loads(proc.stdout)['status']=='READY FOR TVU';results['piped-json']='PASS'
# Parent node selection is bounded and uses observed notary configuration.
company=pathlib.Path('/work/company');company.mkdir()
shutil.copytree('/work/clean/ExampleIssuer',company/'Custodian')
shutil.copytree('/work/clean/ExampleIssuer',company/'Notary')
with (company/'Notary/node.conf').open('a') as conf:conf.write('\nnotary.validating=false\n')
t=Terminal('multiple-node-selection','clean',node=str(company));t.menu();t.shot('19-node-selection.png');assert 'Non-validating notary' in '\n'.join(t.screen.display);t.choose(2);t.menu();assert 'Notary' in '\n'.join(t.screen.display);t.choose(1);t.menu();t.choose(6);t.finish(1)
kit=pathlib.Path('/work/ambiguous-kit');shutil.copytree('/work/clean/upgrade-kit',kit)
shutil.copyfile(kit/'corda.jar',kit/'alternate-runtime.jar');shutil.copyfile(kit/'transaction-validator.jar',kit/'alternate-tool.jar')
t=Terminal('artifact-selection','clean',kit=str(kit));t.menu();t.shot('20-artifact-selection.png');t.choose(1);t.menu();t.choose(1);t.menu();t.choose(1);t.menu();t.choose(6);t.finish(1)
t=Terminal('discovery-exit','clean');t.menu();t.choose(3);t.finish(0);assert b'Assessment was not run' in t.data
shutil.copytree('/work/reports',ROOT/'interactive-artifacts')
(SHOTS/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(ROOT/'interactive-validation.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
