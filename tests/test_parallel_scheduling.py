"""Pool scheduling in scrub_in_parallel: enough tasks to keep every worker
busy, and the longest work first.

Measured before: exactly `jobs` batch tasks, balanced by bytes although cost
is content-dependent, so the slowest bucket set the phase while 15 cores
idled; and the chunks of the biggest files (the critical path) were queued
behind every small-file batch.
"""

import logging

from supportutils_scrub import parallel
from supportutils_scrub.scrub_config import ScrubConfig


class _Inline:
    """A stand-in executor: records the order of submissions, runs inline."""
    submitted = []

    def __init__(self, max_workers=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def map(self, fn, items):
        _Inline.submitted.append(fn.__name__)
        return [fn(i) for i in items]

    def submit(self, fn, *a):
        _Inline.submitted.append(fn.__name__)
        import concurrent.futures
        f = concurrent.futures.Future()
        try:
            f.set_result(fn(*a))
        except Exception as e:
            f.set_exception(e)
        return f


def _tree(tmp_path, small=40, big=1):
    files = []
    for i in range(small):
        p = tmp_path / f"small{i}.txt"
        p.write_text("client 8.8.8.8 connected\n" * 3)
        files.append(str(p))
    for i in range(big):
        p = tmp_path / f"big{i}.log"
        p.write_text("client 8.8.4.4 connected\n" * 400)
        files.append(str(p))
    return files


def _run(tmp_path, monkeypatch, jobs=2):
    monkeypatch.setattr(parallel, "ProcessPoolExecutor", _Inline)
    monkeypatch.setattr(parallel, "_CHUNK_THRESHOLD", 4096)   # big0.log chunks
    _Inline.submitted.clear()
    seen = {}
    real = parallel._balanced_batches

    def spy(files, n):
        seen["n"] = n
        return real(files, n)

    monkeypatch.setattr(parallel, "_balanced_batches", spy)
    cfg = ScrubConfig(obfuscate_private_ip=True, obfuscate_public_ip=True,
                      dataset_dir=str(tmp_path / "ds"))
    parallel.scrub_in_parallel(_tree(tmp_path), {}, cfg, jobs,
                               logging.getLogger("t"))
    return seen


def test_small_files_are_split_into_many_more_tasks_than_workers(
        tmp_path, monkeypatch):
    seen = _run(tmp_path, monkeypatch, jobs=2)
    assert seen["n"] >= 2 * 8


def test_big_file_chunks_are_submitted_before_small_batches(
        tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, jobs=2)
    apply_phase = [n for n in _Inline.submitted
                   if n in ("_scrub_chunk", "_scrub_batch")]
    assert apply_phase, _Inline.submitted
    assert apply_phase[0] == "_scrub_chunk"
