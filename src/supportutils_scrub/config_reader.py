# config_reader.py

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
                for line in config_file:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    key, value = line.split('=', 1)
                    raw[key.strip()] = value.strip()

        except FileNotFoundError:
            print(f"[!] Configuration file not found: {config_path}.", file=sys.stderr)
            print(f"     → Using default settings", file=sys.stderr)
        except Exception as e:
            print(f"[!] Error reading configuration file: {e}", file=sys.stderr)
            print(f"     → Using default settings", file=sys.stderr)

        return ScrubConfig.from_dict(raw)
