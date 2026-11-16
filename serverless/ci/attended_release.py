"""One dated synthetic-image exception. Does not change security_scan policy.

Raw scan must be complete. Unknown new IDs require review before GPU execution;
publication of this synthetic image is not deployment or a security clearance.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from security_scan import assess, expected_packages
from runtime_check import image_ref
from bounded import run

ROOT = Path(__file__).resolve().parent.parent


def eligible(report, image, packages):
    result = assess(report, image, packages)
    if result['suppressed']:
        raise ValueError('suppressed findings')
    rows = report['Results']
    for row in rows:
        for vuln in row.get('Vulnerabilities', []):
            if row.get('Class') != 'os-pkgs' or vuln.get('Severity') not in ('UNKNOWN','LOW','MEDIUM','HIGH'):
                raise ValueError('outside attended exception')
    return dict(result, general_release_passed=result['passed'],
                synthetic_image_publication_exception=True,
                paid_execution_authorized_by_scan=False)


def main():
    e = ROOT/'evidence'
    if datetime.now(timezone.utc).date().isoformat() >= '2026-11-23':
        raise ValueError('exception expired')
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
