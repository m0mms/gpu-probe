"""Single child process diagnostics. Fixed codes and bounded integer facts only."""
CODES = frozenset('''v1_mapping v1_values v1_stability admission_start guard_before guard_after platform
cgroup_read mount_read cgroup_unified cgroup_path cgroup_mount cgroup_mapping
memory_max_read memory_max_parse memory_current_read memory_current_parse
memory_observation memory_ceiling status_read status_parse rss_parse threads_parse
limits_read process_rss process_as process_threads process_environment
driver_discovery driver_binding nvrtc_binding driver_load nvrtc_load
cu_init device_count device_select driver_version compute_major compute_minor
nvrtc_version one_device runtime_compatibility admission_complete'''.split())
FACTS = frozenset('''cgroup_layout_oversize cgroup_v1_memory_memberships cgroup_unified_memberships cgroup_membership_malformed mount_records mount_malformed mount_v1_memory_records mount_v2_records mount_cgroup2_tokens cgroup2_mount_count cgroup_match_count cgroup_identity_count effective_limit rss threads as_soft as_hard
driver_path_mask driver_resolved_count native_return device_count
driver_version nvrtc_major nvrtc_minor compute_major compute_minor'''.split())
_code = 'admission_start'
_facts = {}


def reset():
    global _code, _facts
    _code, _facts = 'admission_start', {}


def mark(code, **facts):
    global _code
    if code not in CODES:
        raise ValueError('invalid diagnostic code')
    if code != _code:
        _facts.pop('native_return', None)
    _code = code
    for key, value in facts.items():
        if key in FACTS and type(value) is int and -(2**63) <= value < 2**63:
            _facts[key] = value


def snapshot():
    return {'code': _code, 'facts': dict(_facts)}


def valid(value):
    return (type(value) is dict and set(value) == {'code', 'facts'}
            and type(value['code']) is str and value['code'] in CODES
            and type(value['facts']) is dict and set(value['facts']) <= FACTS
            and all(type(v) is int and -(2**63) <= v < 2**63
                    for v in value['facts'].values()))
