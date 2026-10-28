"""Pure protocol validation extracted from existing reviewed worker dependencies."""
import hashlib
import json
import math
import re

class Refused(RuntimeError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', value):
        raise Refused('Invalid routing identifier')
    return value

def parsed_object(raw):
    def pairs(items):
        result={}
        for k,v in items:
            if k in result: raise ValueError('duplicate')
            result[k]=v
        return result
    def finite_float(text):
        value=float(text)
        if not math.isfinite(value): raise ValueError('nonfinite')
        return value
    try:
        value=json.loads(raw,object_pairs_hook=pairs,parse_float=finite_float,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(value) is not dict: raise ValueError()
        return value
    except Exception: raise Refused('Invalid transport response') from None
