# det.py -- deterministic fake-value helpers for parallel (--jobs) scrubbing.
#
# In parallel mode each worker process allocates fake values independently, so
# allocation must be a pure function of the real value (not a per-process
# counter) or the same real value could map to different fakes in different
# workers. We use blake2b, KEYED: unkeyed, anyone holding scrubbed output could
# enumerate candidates (an IPv4 is 2^32, hostnames are a dictionary), hash
# them and read the mapping back. The key is generated per fresh run, lives in
# the mapping file (mode 0600) so a --mappings resume reproduces the same
# fakes, and never appears in any output. NOTE: Python's builtin hash() is
# salted per process and must never be used here.

import hashlib
import os

KEY_FIELD = 'det_key'
_KEY = None            # bytes, or None for the legacy unkeyed digest


def set_key(hex_key):
    """Install the run's key (hex string) or None for the unkeyed digest."""
    global _KEY
    _KEY = bytes.fromhex(hex_key) if hex_key else None


def current_key():
    return _KEY.hex() if _KEY else None


def ensure_key(mappings):
    """Install the key a mapping carries; give a FRESH mapping a new one.

    A legacy mapping (values already present, no key) stays unkeyed: the
    cases scrubbed with it must keep their fakes on every re-sync."""
    key = mappings.get(KEY_FIELD) if isinstance(mappings, dict) else None
    if key:
        set_key(key)
        return key
    has_values = any(isinstance(v, dict) and v for k, v in mappings.items()
                     if k != KEY_FIELD)
    if has_values:
        set_key(None)
        return None
    key = os.urandom(16).hex()
    mappings[KEY_FIELD] = key
    set_key(key)
    return key


def dhash(value: str, nbytes: int = 6) -> str:
    """Stable lowercase hex digest of `value`, `nbytes` bytes wide."""
    data = value.encode('utf-8', 'surrogatepass')
    if _KEY:
        return hashlib.blake2b(data, digest_size=nbytes, key=_KEY).hexdigest()
    return hashlib.blake2b(data, digest_size=nbytes).hexdigest()
