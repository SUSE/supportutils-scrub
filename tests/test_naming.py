"""Output naming contract (docs/naming-convention.md).

These input -> output pairs are a frozen contract: '_scrubbed' appears
exactly once, before the file extension, with a compression extension
outermost. Changing an expected value here is a breaking change for
users and must not happen casually.
"""
import gzip
import lzma

import pytest

from supportutils_scrub.processor import FileProcessor, scrubbed_output_name, append_scrubbed
from supportutils_scrub.pipeline import scrub_name
from supportutils_scrub.pcap_rewrite import _dest_paths


class _Logger:
    def info(self, msg): pass
    def error(self, msg): pass
    def warning(self, msg): pass


SINGLE_FILE_CASES = [
    # plain file: marker before the extension
    ("messages.log", "messages_scrubbed.log"),
    # no extension
    ("messages", "messages_scrubbed"),
    # only the last extension counts
    ("app.error.log", "app.error_scrubbed.log"),
    # a dotfile's whole name is the root
    (".env", ".env_scrubbed"),
    # casing preserved, extension matching case-insensitive
    ("MESSAGES.LOG", "MESSAGES_scrubbed.LOG"),
    # compression extension stays outermost
    ("messages.log.xz", "messages_scrubbed.log.xz"),
    ("boot.log.bz2", "boot_scrubbed.log.bz2"),
    ("MESSAGES.LOG.XZ", "MESSAGES_scrubbed.LOG.XZ"),
    # compressed with no inner extension
    ("traces.gz", "traces_scrubbed.gz"),
    # idempotent: re-running never doubles the marker
    ("messages_scrubbed.log", "messages_scrubbed.log"),
    ("messages_scrubbed", "messages_scrubbed"),
    ("messages_scrubbed.log.xz", "messages_scrubbed.log.xz"),
    # directory part is preserved untouched
    ("/var/log/messages.log", "/var/log/messages_scrubbed.log"),
]


@pytest.mark.parametrize("given,expected", SINGLE_FILE_CASES)
def test_single_file_names(given, expected):
    assert scrubbed_output_name(given) == expected


FOLDER_AND_ARCHIVE_CASES = [
    # loose folder and archive base names: marker appended once
    ("mylogs", "mylogs_scrubbed"),
    ("scc_host001_250101_1200", "scc_host001_250101_1200_scrubbed"),
    # idempotent
    ("mylogs_scrubbed", "mylogs_scrubbed"),
    ("scc_host001_250101_1200_scrubbed", "scc_host001_250101_1200_scrubbed"),
]


@pytest.mark.parametrize("given,expected", FOLDER_AND_ARCHIVE_CASES)
def test_folder_and_archive_names(given, expected):
    assert append_scrubbed(given) == expected


PCAP_CASES = [
    ("capture.pcap", "/out/capture_scrubbed.pcap"),
    # extensionless capture gets .pcap
    ("capture", "/out/capture_scrubbed.pcap"),
    ("capture_scrubbed.pcap", "/out/capture_scrubbed.pcap"),
]


@pytest.mark.parametrize("given,expected", PCAP_CASES)
def test_pcap_names(given, expected):
    tmp, fout = _dest_paths("/out", given)
    assert fout == expected
    assert tmp == expected + ".tmp"


def test_hostname_obfuscated_in_output_name():
    # hostnames/domains in the input name never survive into the output name
    hostname_dict = {"myhost": "host001"}
    domain_dict = {"example.com": "domain_0"}
    base = scrub_name("myhost.example.com.log", hostname_dict, domain_dict=domain_dict)
    assert scrubbed_output_name(base) == "host001.domain_0_scrubbed.log"


# --- --unpacked: compression is dropped instead of preserved -----------------

UNPACKED_SINGLE_FILE_CASES = [
    # (input, compression ext stripped before naming) -> plain output name
    ("messages.log.xz", ".xz", "messages_scrubbed.log"),
    ("boot.log.bz2", ".bz2", "boot_scrubbed.log"),
    ("traces.gz", ".gz", "traces_scrubbed"),
]


@pytest.mark.parametrize("given,comp_ext,expected", UNPACKED_SINGLE_FILE_CASES)
def test_unpacked_single_file_names(given, comp_ext, expected):
    assert scrubbed_output_name(given[:-len(comp_ext)]) == expected


def test_unpacked_decompresses_in_tree_files(tmp_path):
    # inside a folder/archive tree, --unpacked writes compressed files back
    # plain (same name minus the compression extension) and removes the original
    gz = tmp_path / "boot.log.gz"
    with gzip.open(gz, "wt") as f:
        f.write("hello\n")
    xz = tmp_path / "messages.log.xz"
    with lzma.open(xz, "wt") as f:
        f.write("world\n")

    fp = FileProcessor(None, [], decompress=True)
    fp.process_file(str(gz), _Logger(), False)
    fp.process_file(str(xz), _Logger(), False)

    assert not gz.exists()
    assert (tmp_path / "boot.log").read_text() == "hello\n"
    assert not xz.exists()
    assert (tmp_path / "messages.log").read_text() == "world\n"


def test_default_keeps_compression(tmp_path):
    # without --unpacked, compressed files keep their name and format
    gz = tmp_path / "boot.log.gz"
    with gzip.open(gz, "wt") as f:
        f.write("hello\n")

    fp = FileProcessor(None, [])
    fp.process_file(str(gz), _Logger(), False)

    assert gz.exists()
    with gzip.open(gz, "rt") as f:
        assert f.read() == "hello\n"
