# config.py

import os as _os

# /etc takes priority (administrator override).
# /usr/etc is the vendor layer on SLES 16 and later.
_CANDIDATES = [
    "/etc/supportutils-scrub/supportutils-scrub.conf",
    "/usr/etc/supportutils-scrub/supportutils-scrub.conf",
]

DEFAULT_CONFIG_PATH = next(
    (p for p in _CANDIDATES if _os.path.exists(p)),
    _CANDIDATES[0],
)

