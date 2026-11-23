"""Approved one-attempt OS-only exception; general security gate is unchanged."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from security_scan import assess, expected_packages
from runtime_check import image_ref
from bounded import run

ROOT = Path(__file__).resolve().parent.parent


BASELINE_SHA256='0ed7fd886e57d9cf88883377f6c4da23967360ab7f2b2a98668fce07fbd623ee'

def baseline():
    raw=(Path(__file__).resolve().parent/'publication-baseline.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BASELINE_SHA256:raise ValueError('publication baseline drift')
    return json.loads(raw)

def window(now):
    if now.tzinfo is None or now>=datetime(2026,11,25,15,13,tzinfo=timezone.utc):
        raise ValueError('exception expired or timezone absent')

def package_version(pkg):
    version=pkg.get('Version')
    release=pkg.get('Release','')
    epoch=pkg.get('Epoch',0)
    if type(version) is not str or not version or type(release) is not str or type(epoch) is not int or epoch<0:
        raise ValueError('malformed package version')
    return (str(epoch)+':' if epoch else '')+version+('-'+release if release else '')

def eligible(report, image, packages, accepted=None):
    result = assess(report, image, packages)
    if result['suppressed']:
        raise ValueError('suppressed findings')
    approved=baseline() if accepted is None else accepted
    actual=[]
    for row in report['Results']:
        if (row.get('Class'),row.get('Type')) not in (('os-pkgs','debian'),('lang-pkgs','python-pkg')):
            raise ValueError('unexpected inventory class')
        for pkg in row.get('Packages',[]):
            item=[row['Class'],row['Type'],pkg.get('Name'),package_version(pkg),pkg.get('FilePath',''),pkg.get('Arch','')]
            if any(type(v) is not str for v in item) or not item[2] or not item[3]:
                raise ValueError('malformed package identity')
            actual.append(item)
    if sorted(actual)!=approved['inventory']:
        raise ValueError('dependency inventory drift')
    known={tuple(v[k] for k in ('VulnerabilityID','PkgName','InstalledVersion','Severity')) for v in approved['findings']}
    delta=[]
    os_packages={(p[2],p[3]) for p in actual if p[0]=='os-pkgs'}
    for row in report['Results']:
        for vuln in row.get('Vulnerabilities', []):
            if row.get('Class') != 'os-pkgs' or vuln.get('Severity') not in ('UNKNOWN','LOW','MEDIUM','HIGH'):
                raise ValueError('outside attended exception')
            item=tuple(vuln.get(k) for k in ('VulnerabilityID','PkgName','InstalledVersion','Severity'))
            if not all(type(v) is str and v for v in item) or (item[1],item[2]) not in os_packages:
                raise ValueError('malformed or unbound vulnerability identity')
            if item not in known:
                delta.append(dict(zip(('VulnerabilityID','PkgName','InstalledVersion','Severity'),item)))
    return dict(result, general_release_passed=result['passed'],
                noncritical_os_delta=delta, dependency_inventory_matched=True,
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
