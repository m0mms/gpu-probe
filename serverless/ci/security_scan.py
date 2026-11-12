"""Inherited fail-closed scanner policy, now requiring OS and installed Python coverage."""
import json,os,re,tempfile
from datetime import datetime,timezone
from pathlib import Path
from bounded import run
from runtime_check import image_ref
ROOT=Path(__file__).resolve().parent.parent

def normalized(n):return re.sub('[-_.]+','-',n).lower()
def expected_packages():
    return {normalized(n):v for n,v in re.findall(r'^([a-zA-Z0-9_.-]+)==([^ \\n]+)',(ROOT/'image/requirements.lock').read_text(),re.M)}
def assess(report,image,expected):
    meta=report.get('Metadata',{})
    if meta.get('ImageID')!=image:raise ValueError('scan image binding')
    if meta.get('OS',{}).get('Family')!='debian' or str(meta.get('OS',{}).get('Name','')).split('.')[0]!='12':raise ValueError('OS coverage')
    results=report.get('Results')
    if not isinstance(results,list):raise ValueError('scan results')
    osrows=[r for r in results if r.get('Class')=='os-pkgs' and r.get('Type')=='debian']
    pyrows=[r for r in results if r.get('Class')=='lang-pkgs' and r.get('Type')=='python-pkg']
    if len(osrows)!=1 or not osrows[0].get('Packages') or not pyrows:raise ValueError('missing inventory')
    actual={}
    for row in pyrows:
        for pkg in row.get('Packages',[]):actual.setdefault(normalized(pkg['Name']),set()).add(pkg['Version'])
    if not expected or any(actual.get(n)!={v} for n,v in expected.items()):raise ValueError('locked Python coverage')
    findings=sum(len(r.get('Vulnerabilities',[])) for r in results)
    suppressed=sum(len(r.get('ExperimentalModifiedFindings',[])) for r in results)
    return {'passed':findings==0 and suppressed==0,'findings':findings,'suppressed':suppressed,'locked_python_packages':len(expected),'scope':'OS/Python vulnerability assessment, not complete security clearance'}

def main():
    e=ROOT/'evidence';e.mkdir(exist_ok=True);image=image_ref(os.environ['BUILT_IMAGE_ID'])
    with tempfile.TemporaryDirectory() as temp:
        p=Path(temp);(p/'config').write_text('{}\n');(p/'ignore').write_text('')
        env={k:v for k,v in os.environ.items() if not k.startswith('TRIVY_')}
        args=['trivy','image','--config',str(p/'config'),'--cache-dir',str(p/'cache'),'--image-src','docker','--scanners','vuln','--pkg-types','os,library','--list-all-pkgs','--ignorefile',str(p/'ignore'),'--show-suppressed','--disable-telemetry','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--timeout','8m','--format','json','--exit-code','0',image]
        code,out,err=run(args,env=env,timeout=540,cap=16*1024**2)
        (e/'scanner-status.json').write_text(json.dumps({'exit_code':code,'stderr':err.decode(errors='replace')})+'\n')
        if code:raise ValueError('scanner failed')
        (e/'trivy.json').write_bytes(out)
        code,version,err=run(['trivy','--version','--format','json','--cache-dir',str(p/'cache')],env=env)
        if code:raise ValueError('scanner version')
        (e/'scanner-version.json').write_bytes(version);v=json.loads(version)
        if v.get('Version')!='0.76.1':raise ValueError('scanner pin')
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(v['VulnerabilityDB']['UpdatedAt'].replace('Z','+00:00'))).total_seconds()
        if not 0<=age<=86400:raise ValueError('database age')
        verdict=assess(json.loads(out),image,expected_packages());(e/'security.json').write_text(json.dumps(verdict)+'\n')
        if not verdict['passed']:raise ValueError('findings require disposition; blocked')
if __name__=='__main__':main()
