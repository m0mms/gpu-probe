"""Source-staging helpers only; no infrastructure operations."""
LIMITS={'disk_bytes':5000000000,'download_bytes':1073741824}
class Refusal(ValueError):pass
def require(ok,message):
    if not ok:raise Refusal(message)
