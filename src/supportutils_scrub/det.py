# det.py — deterministic fake-value helpers for parallel (--jobs) scrubbing.
#
# In parallel mode each worker process allocates fake values independently, so
# allocation must be a pure function of the real value (not a per-process
# counter) or the same real value could map to different fakes in different
# workers. We use blake2b — a stable, fast, unsalted hash. NOTE: Python's
# builtin hash() is salted per process and must never be used here.

import hashlib


def dhash(value: str, nbytes: int = 6) -> str:
    """Stable lowercase hex digest of `value`, `nbytes` bytes wide."""
    data = value.encode('utf-8', 'surrogatepass')
    return hashlib.blake2b(data, digest_size=nbytes).hexdigest()
