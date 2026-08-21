"""verify.py mirrors the password scrubber (a pattern change is a two-file
change): the residual scan must flag every credential form the scrubber
now replaces, or a scrub that missed one passes verification."""

import os

from supportutils_scrub.verify import verify_scrubbed_folder

SECRET = "Qx7~vB2mK9pLd4RtZ0aWcE1sYn6Uf8Hj3Gk5"


def _findings(tmp_path, name, text):
    d = tmp_path / "scrubbed"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text)
    return verify_scrubbed_folder(str(d), {}, check_identity=False, jobs=1)


def test_attribute_pair_credential_is_flagged(tmp_path):
    f = _findings(tmp_path, "cib.xml",
                  f'<nvpair id="a2" name="passwd" value="{SECRET}"/>\n')
    assert any(SECRET in x["value"] for x in f), f


def test_secret_with_symbols_is_flagged_whole(tmp_path):
    f = _findings(tmp_path, "ha.txt", f"params passwd={SECRET} ssl=1\n")
    assert any(SECRET in x["value"] for x in f), f


def test_scrubbed_forms_are_not_flagged(tmp_path):
    f = _findings(tmp_path, "cib.xml",
                  '<nvpair name="passwd" value="scrubbed_pass_1"/>\n'
                  'password=scrubbed_pass_2\n')
    assert not [x for x in f if x["category"] == "password value"], f
