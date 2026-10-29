"""Run standard Trivy; preserve all findings and fail closed pending disposition."""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from bounded import run
from identity import qualification_reference


def assess(report, image):
    meta = report.get('Metadata', {})
    if meta.get('OS', {}).get('Family') != 'debian' or str(meta.get('OS', {}).get('Name', '')).split('.')[0] != '12':
        raise ValueError('unexpected or missing distro coverage')
    if meta.get('ImageID') != image:
        raise ValueError('scan image identity mismatch')
    results = report.get('Results')
    if not isinstance(results, list):
        raise ValueError('missing scan results')
    os_results = [r for r in results if r.get('Class') == 'os-pkgs' and r.get('Type') == 'debian']
    if len(os_results) != 1 or not os_results[0].get('Packages'):
        raise ValueError('missing Debian package inventory')
    actual = {v['Name'].split(':')[0]:v['Version'] for v in os_results[0]['Packages']}
    expected = json.loads(Path(__file__).with_name('expected-packages.json').read_text())
    if actual != expected:
        raise ValueError('package inventory changed; source coverage review required')
    findings = sum(len(r.get('Vulnerabilities', [])) for r in results)
    suppressed = sum(len(r.get('ExperimentalModifiedFindings', [])) for r in results)
    return {'findings': findings, 'suppressed': suppressed, 'passed': findings == 0 and suppressed == 0,
            'policy': 'Any finding requires explicit review; no automatic risk acceptance',
            'scope': 'Debian OS package scan only; not application or runtime security clearance'}


def main():
    image = qualification_reference(os.environ['QUALIFY_IMAGE'], 'local-build')
    evidence = Path(os.environ['EVIDENCE_DIR']); evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp); (root/'config.yaml').write_text('{}\n'); (root/'ignore').write_text('')
        env = {k:v for k,v in os.environ.items() if not k.startswith('TRIVY_')}
        args = ['trivy', 'image', '--config', str(root/'config.yaml'), '--cache-dir', str(root/'cache'),
                '--image-src', 'docker', '--scanners', 'vuln', '--pkg-types', 'os', '--list-all-pkgs',
                '--ignorefile', str(root/'ignore'), '--show-suppressed', '--disable-telemetry',
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--timeout', '8m',
                '--format', 'json', '--exit-code', '0', image]
        code, out, err = run(args, env=env, timeout=540, cap=8*1024**2)
        if code:
            (evidence/'scanner-stderr.json').write_text(json.dumps({'returncode':code,'stderr':err.decode('utf-8',errors='replace')})+'\n')
            raise ValueError('scanner failed; no security acceptance')
        (evidence/'trivy.json').write_bytes(out)
        version_code, version, version_err = run(['trivy', '--version', '--format', 'json', '--cache-dir', str(root/'cache')], env=env)
        if version_code:
            raise ValueError('scanner identity missing')
        (evidence/'trivy-version.json').write_bytes(version)
        metadata = json.loads(version)
        if metadata.get('Version') != '0.76.1':
            raise ValueError('unexpected scanner version')
        updated = datetime.fromisoformat(metadata['VulnerabilityDB']['UpdatedAt'].replace('Z', '+00:00'))
        if not 0 <= (datetime.now(timezone.utc)-updated).total_seconds() <= 86400:
            raise ValueError('scanner database freshness not established')
        verdict = assess(json.loads(out), image)
        (evidence/'security-decision.json').write_text(json.dumps(verdict, indent=2)+'\n')
        if not verdict['passed']:
            raise ValueError('findings require explicit disposition; publication blocked')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        evidence = Path(os.environ['EVIDENCE_DIR']); evidence.mkdir(parents=True, exist_ok=True)
        (evidence/'scanner-failure.json').write_text(json.dumps({'passed':False,'error_type':type(exc).__name__,
            'message':str(exc)[:1024], 'scope':'Diagnostic only; failure is never security acceptance'},indent=2)+'\n')
        raise
