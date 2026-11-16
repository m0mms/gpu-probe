"""Fixed stage names only: never serialize exceptions or child diagnostics."""
STAGES = frozenset({
    'package_binding', 'attempt_claim', 'resource_limits', 'module_import',
    'guard_creation', 'runtime_admission', 'native_qualification',
    'result_checks', 'receipt_encoding', 'runner_setup',
    'child_timeout', 'child_exit', 'child_output', 'child_receipt',
    'child_start', 'handler_internal',
})


def failed(stage):
    if type(stage) is not str or stage not in STAGES:
        stage = 'handler_internal'
    return {'status': 'synthetic_native_fail', 'reason': 'qualification_failed',
            'stage': stage}


def valid_failure(value):
    from admission_diagnostics import valid
    if type(value) is not dict:
        return False
    keys = set(value)
    if keys not in ({'status', 'reason', 'stage'}, {'status', 'reason', 'stage', 'admission'}):
        return False
    if not (value.get('status') == 'synthetic_native_fail'
            and value.get('reason') == 'qualification_failed'
            and type(value.get('stage')) is str and value['stage'] in STAGES):
        return False
    return ('admission' not in value or
            (value['stage'] == 'runtime_admission' and valid(value['admission'])))
