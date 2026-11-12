"""Client acceptance: provider completion alone is never scientific success."""
PASS = {"status": "synthetic_native_pass", "elements": 257,
        "numeric_exact": True, "negative_compile_control": True,
        "owned_context_cleanup": True, "provider_cleanup_verified": False,
        "scientific_operator_qualified": False}

def accepted(response, expected_job_id):
    if type(expected_job_id) is not str or not expected_job_id:
        return False
    if type(response) is not dict or response.get("id") != expected_job_id:
        return False
    if response.get("status") != "COMPLETED" or "error" in response:
        return False
    out = response.get("output")
    return (type(out) is dict and out == PASS
            and all(type(out[k]) is type(v) for k, v in PASS.items()))
