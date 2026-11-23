"""One dated synthetic-image exception. Does not change security_scan policy.

Raw scan must be complete. New IDs/packages/versions or severity increases refuse;
publication of this synthetic image is not deployment or a security clearance.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from security_scan import assess, expected_packages
from runtime_check import image_ref
from bounded import run

ROOT = Path(__file__).resolve().parent.parent


BASELINE_SHA256='dcb3b1b5488fc2fefffecad754e7cc3f1d4ade21597016f7ae42334105d9ac24'

def baseline():
    raw=(Path(__file__).resolve().parent/'publication-baseline.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASELINE_SHA256:raise ValueError('publication baseline drift')
    return json.loads(raw)

def window(now):
    if now.tzinfo is None or now>=datetime(2026,11,25,tzinfo=timezone.utc):
        raise ValueError('exception expired or timezone absent')

def eligible(report, image, packages, accepted=None):
    result = assess(report, image, packages)
    if result['suppressed']:
        raise ValueError('suppressed findings')
    approved=baseline() if accepted is None else accepted
    limits={}
    for item in approved['findings']:
        key=tuple(item[k] for k in ('VulnerabilityID','PkgName','InstalledVersion'))
        limits.setdefault(key,set()).add(item['Severity'])
    ranks={'LOW':1,'MEDIUM':2,'HIGH':3}
    rows = report['Results']
    for row in rows:
        for vuln in row.get('Vulnerabilities', []):
            if row.get('Class') != 'os-pkgs' or vuln.get('Severity') not in ('UNKNOWN','LOW','MEDIUM','HIGH'):
                raise ValueError('outside attended exception')
            key=tuple(vuln.get(k) for k in ('VulnerabilityID','PkgName','InstalledVersion'))
            if not all(type(x) is str and x for x in key) or key not in limits:
                raise ValueError('new or malformed vulnerability identity')
            severity=vuln['Severity'];known=limits[key]
            if severity not in known and not (severity in ranks and any(s in ranks and ranks[severity]<=ranks[s] for s in known)):
                raise ValueError('severity escalation or unknown reassessment')
    return dict(result, general_release_passed=result['passed'],
                synthetic_image_publication_exception=True,
                paid_execution_authorized_by_scan=False)


def main():
    e = ROOT/'evidence'
    window(datetime.now(timezone.utc))
    if os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        raise ValueError('no CI rerun')
    image = image_ref(os.environ['BUILT_IMAGE_ID'])
    version = json.loads((e/'scanner-version.json').read_text())
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(version['VulnerabilityDB']['UpdatedAt'].replace('Z','+00:00'))).total_seconds()
    if version.get('Version')!='0.76.1' or not 0<=age<=86400:
        raise ValueError('scanner/version age')
    if json.loads((e/'scanner-status.json').read_text())['exit_code'] != 0:
        raise ValueError('scanner failed')
    for name in ('cleanup.json','capture-cleanup.json'):
        if json.loads((e/name).read_text()).get('clear') is not True:
            raise ValueError('CI container cleanup unverified')
    result = eligible(json.loads((e/'trivy.json').read_text()),image,expected_packages())
    (e/'attended-exception.json').write_text(json.dumps(result)+'\n')


if __name__=='__main__':main()
