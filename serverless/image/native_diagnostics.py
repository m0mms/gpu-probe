"""Finite native diagnostics; never inspect or serialize exception contents."""
from native_operations import OPERATIONS

_STATE = None

def reset():
    global _STATE
    _STATE = {'phase': 'positive', 'first': None, 'terminal': None, 'cleanup': None}


def negative_phase():
    # Positive qualification has completed before this boundary.
    reset()
    _STATE['phase'] = 'negative_control'


def _record(site, kind, status=None):
    event = {'operation': site, 'kind': kind, 'status': status}
    if _STATE['first'] is None:
        _STATE['first'] = event
    _STATE['terminal'] = event
    if OPERATIONS[site]['cleanup'] and _STATE['cleanup'] is None:
        _STATE['cleanup'] = event


def invoke(site, operation):
    # Site names are static source constants, never supplied by a job.
    if site not in OPERATIONS:
        raise RuntimeError('unknown diagnostic site')
    try:
        value = operation()
    except BaseException:
        _record(site, 'exception')
        raise
    if OPERATIONS[site]['native_status'] and type(value) is int and value != 0:
        _record(site, 'native_status', value if -(2**31) <= value < 2**31 else None)
    return value


def raising(site, error):
    if site not in OPERATIONS:raise RuntimeError('unknown diagnostic site')
    _record(site, 'exception')
    return error


def snapshot():
    return {k: dict(v) if type(v) is dict else v for k,v in _STATE.items()}


def valid(value):
    if type(value) is not dict or set(value) != {'phase','first','terminal','cleanup'}:
        return False
    if type(value['phase']) is not str or value['phase'] not in ('positive','negative_control'):
        return False
    for key in ('first','terminal','cleanup'):
        e=value[key]
        if e is None:
            continue
        if type(e) is not dict or set(e) != {'operation','kind','status'}:
            return False
        site=e['operation']
        if type(site) is not str or site not in OPERATIONS:
            return False
        if type(e['kind']) is not str or e['kind'] not in ('exception','native_status'):
            return False
        if key=='cleanup' and not OPERATIONS[site]['cleanup']:
            return False
        if e['kind']=='exception':
            if e['status'] is not None:return False
        elif not OPERATIONS[site]['native_status'] or not (e['status'] is None or
              type(e['status']) is int and -(2**31)<=e['status']<2**31 and e['status']!=0):
            return False
    return (value['first'] is None)==(value['terminal'] is None) and (value['cleanup'] is None or value['first'] is not None)

reset()
