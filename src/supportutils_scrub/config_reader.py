# config_reader.py

import re
import sys
from supportutils_scrub.scrub_config import ScrubConfig


class ConfigReader:
    def __init__(self, default_config_path):
        self.default_config_path = default_config_path

    def read_config(self, config_path=None):

        if config_path is None:
            config_path = self.default_config_path

        raw = {}

        try:
            with open(config_path, "r") as config_file:
                for n, line in enumerate(config_file, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        continue
                    key, eq, value = line.partition('=')
                    if not eq or not key.strip():
                        print(f"[!] {config_path}:{n}: not 'key = value', ignored: {line}",
                              file=sys.stderr)
                        continue
                    # inline comment: "obfuscate_domain = yes   # keep on"
                    raw[key.strip()] = re.split(r'\s+#', value, 1)[0].strip()

        except FileNotFoundError:
            print(f"[!] Configuration file not found: {config_path}.", file=sys.stderr)
            print(f"     → Using default settings", file=sys.stderr)
        except Exception as e:
            print(f"[!] Error reading configuration file: {e}", file=sys.stderr)
            print(f"     → Using default settings", file=sys.stderr)

        return ScrubConfig.from_dict(raw)
