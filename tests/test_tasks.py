import io
import json
from pathlib import Path
import zipfile

import pytest

from src import tasks


def test_parse_clamscan_output_infected():
    sample_output = """\
/tmp/test/file1.txt: OK
/tmp/test/file2.txt: Eicar-Test-Signature FOUND
----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.2.3
Scanned directories: 1
Scanned files: 2
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.001 sec (0 m 0 s)
"""
    items, summary = tasks.parse_clamscan_output(sample_output)

    assert len(items) == 2
    assert any(item["result"] == "FOUND" for item in items)
    assert summary["Infected files"] == "1"


def test_extract_archive_zip(tmp_path):
    zip_path = tmp_path / "collection.zip"
    inner = tmp_path / "inner"
    inner.mkdir()
    payload = inner / "hello.txt"
    payload.write_text("hi", encoding="utf-8")

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(payload, arcname="hello.txt")

    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()

    extracted = tasks._extract_archive(zip_path, staging_dir)
    assert extracted.is_dir()
    assert (extracted / "hello.txt").read_text(encoding="utf-8") == "hi"


def test_run_clamscan_parses_results_and_reports_progress(mocker, tmp_path):
    sample_output = """\
/tmp/collection/hello.txt: Eicar-Test-Signature FOUND
----------- SCAN SUMMARY -----------
Infected files: 1
"""

    class FakeProcess:
        def __init__(self):
            self.stdout = io.StringIO(sample_output)
            self.stderr = io.StringIO("")
            self.returncode = 1

        def wait(self):
            return self.returncode

    mocker.patch("src.tasks.subprocess.Popen", return_value=FakeProcess())

    target = tmp_path / "collection"
    target.mkdir()

    progress_calls = []

    def _progress(processed, total, infected, current):
        progress_calls.append((processed, total, infected, current))

    result = tasks.run_clamscan(
        target,
        include_clean=False,
        total_files=1,
        progress_cb=_progress,
    )

    assert result["infected"] is True
    assert result["summary"]["Infected files"] == "1"
    assert result["items"][0]["signature"] == "Eicar-Test-Signature"
    assert progress_calls[0][0] == 0  # initial progress event
    assert progress_calls[-1][0] == 1


def test_write_infected_only_report(tmp_path):
    scan_result = {
        "items": [
            {"path": "/tmp/a.txt", "result": "OK", "signature": None},
            {"path": "/tmp/b.txt", "result": "FOUND", "signature": "Test-Sig"},
        ],
        "summary": {"Infected files": "1"},
    }

    created = tasks._write_infected_only_report(str(tmp_path), "sample", scan_result)
    assert created is not None
    content = json.loads(Path(created.path).read_text(encoding="utf-8"))
    assert content["infected_count"] == 1
    assert content["items"][0]["path"] == "/tmp/b.txt"
