import sys
import pytest
from supportutils_scrub import cli


def _parse(argv):
    orig = sys.argv
    sys.argv = ['supportutils-scrub'] + argv
    try:
        return cli.parse_args()
    finally:
        sys.argv = orig


class TestReportFlags:
    def test_no_report_default(self):
        args = _parse(['/some/path.txz'])
        assert args.report is False
        assert args.report_file is None

    def test_plain_report_flag(self):
        args = _parse(['--report', '/some/path.txz'])
        assert args.report is True
        assert args.report_file is None

    def test_report_file_explicit(self):
        args = _parse(['--report-file', '/tmp/r.json', '/some/path.txz'])
        assert args.report_file == '/tmp/r.json'

    def test_report_file_does_not_steal_positional(self):
        args = _parse(['--report-file', '/tmp/r.json', '/archive.txz'])
        assert args.supportconfig_path == ['/archive.txz']
        assert args.report_file == '/tmp/r.json'
