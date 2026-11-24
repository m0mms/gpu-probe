"""Client acceptance: provider completion alone is never scientific success."""
import re

PASS = {"status": "synthetic_native_pass", "elements": 257,
        "numeric_exact": True, "negative_compile_control": True,
        "owned_context_cleanup": True, "provider_cleanup_verified": False,
        "scientific_operator_qualified": False}


def valid_output(out):
    if type(out) is not dict or set(out) != set(PASS) | {'evidence'}:
        return False
    if any(type(out[k]) is not type(v) or out[k] != v for k, v in PASS.items()):
        return False
    e = out['evidence']
    if type(e) is not dict or set(e) != {'package_freeze', 'native_identity',
            'peak_sampled_rss', 'effective_memory_limit', 'hidden_ancestors_verified',
            'provider_admission_verified'}:
        return False
    if e['package_freeze'] != '2f5f212e97f3858c250ea383370b2fb95604c248d7beb388b1b06825c42af288':
        return False
    if e['hidden_ancestors_verified'] is not False or e['provider_admission_verified'] is not False:
        return False
    for key, limit in (('peak_sampled_rss', 6 * 2**30), ('effective_memory_limit', 64 * 2**30)):
        if type(e[key]) is not int or not 0 < e[key] <= limit:
            return False
    n = e['native_identity']
    hashes = {'driver_sha256', 'nvrtc_sha256', 'ptx_sha256', 'compile_log_sha256'}
    if type(n) is not dict or set(n) != hashes | {'device_ordinal', 'compute', 'driver_version', 'nvrtc_version'}:
        return False
    if any(type(n[k]) is not str or not re.fullmatch('[0-9a-f]{64}', n[k]) for k in hashes):
        return False
    return (type(n['device_ordinal']) is int and n['device_ordinal'] == 0
            and type(n['driver_version']) is int and 12090 <= n['driver_version'] < 100000
            and type(n['compute']) is list and n['compute'] == [8, 6]
            and type(n['nvrtc_version']) is list and n['nvrtc_version'] == [12, 9]
            and all(type(v) is int for k in ('compute', 'nvrtc_version') for v in n[k]))

def accepted(response, expected_job_id):
    if type(expected_job_id) is not str or not expected_job_id:
        return False
    if type(response) is not dict or response.get("id") != expected_job_id:
        return False
    if response.get("status") != "COMPLETED" or "error" in response:
        return False
    out = response.get("output")
    return valid_output(out)
