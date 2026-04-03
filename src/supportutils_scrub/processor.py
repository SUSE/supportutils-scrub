# processor.py

import os
import lzma
import re
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger


_CONFIG_GATES = {
    'ip':       lambda cfg: cfg.obfuscate_public_ip or cfg.obfuscate_private_ip,
    'ipv6':     lambda cfg: cfg.obfuscate_ipv6,
    'mac':      lambda cfg: cfg.obfuscate_mac,
    'hostname': lambda cfg: cfg.obfuscate_hostname,
    'domain':   lambda cfg: cfg.obfuscate_domain,
    'user':     lambda cfg: cfg.obfuscate_username,
}


class FileProcessor:
    def __init__(self, config, scrubbers):
        self.config = config
        self.scrubbers = list(scrubbers)
        self._by_name = {s.name: s for s in self.scrubbers}

        for s in self.scrubbers:
            if isinstance(s, KeywordScrubber) and not s.is_loaded():
                s.load_keywords()

    def __getitem__(self, name):
        return self._by_name.get(name)

    def process_file(self, file_path, logger: SupportutilsScrubLogger, verbose_flag):
        BINARY_SA_PATTERN = re.compile(r"^sa\d{8}(\.xz)?$")
        BINARY_OBJ_PATTERN = re.compile(r"^.*\.obj$", re.IGNORECASE)
        base_name = os.path.basename(file_path)

        if BINARY_SA_PATTERN.match(base_name) or BINARY_OBJ_PATTERN.match(base_name):
            print(f"        {base_name} [binary] (removed)")
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"[!] Failed to remove binary file {file_path}: {e} ")
            return

        SAR_XZ_PATTERN   = re.compile(r'^sar\d{8}\.xz$')
        SAR_PLAIN_PATTERN = re.compile(r'^sar\d{8}$')
        is_sar_xz_file   = bool(SAR_XZ_PATTERN.match(base_name))
        is_sar_plain_file = bool(SAR_PLAIN_PATTERN.match(base_name))

        _SCRUB_INFO_HEADER = (
            "#" + "-" * 93 + "\n"
            "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n"
            "#" + "-" * 93 + "\n\n"
        )

        try:
            if is_sar_xz_file:
                with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()

                scrubbed_first_line = self._scrub_content(first_line, base_name, logger)

                if scrubbed_first_line != first_line:
                    with lzma.open(file_path, mode="rt", encoding="utf-8", errors="ignore") as f:
                        f.readline()
                        rest = f.read()
                    plain_path = file_path[:-3]
                    with open(plain_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_first_line + rest)
                    os.remove(file_path)

            elif is_sar_plain_file:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()
                    rest = f.read()

                scrubbed_first_line = self._scrub_content(first_line, base_name, logger)

                if scrubbed_first_line != first_line:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_first_line + rest)

            else:
                with open(file_path, mode="r", encoding="utf-8", errors="ignore") as file:
                    original_text = file.read()

                scrubbed_text = self._scrub_content(original_text, base_name, logger)

                if scrubbed_text != original_text:
                    with open(file_path, mode="w", encoding="utf-8") as out_f:
                        out_f.write(_SCRUB_INFO_HEADER + scrubbed_text)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")

    def _scrub_content(self, text, basename, logger):
        for scrubber in self.scrubbers:
            gate = _CONFIG_GATES.get(scrubber.name)
            if gate and not gate(self.config):
                continue
            if scrubber.skip_files and basename in scrubber.skip_files:
                continue
            try:
                text = scrubber.scrub(text)
            except Exception as e:
                logger.error(f"{scrubber.name} scrub failed for {basename}: {e}")
        return text

    def process_text(self, text, logger, verbose_flag):
        return self._scrub_content(text, "stdin", logger)
