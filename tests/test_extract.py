import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from whiff import (
    AccessError,
    InvalidOptionError,
    NotFoundError,
    UnsupportedInputError,
    extract,
    llm,
    schema,
    version,
)
from whiff.options import LIMIT_CAPS

ROOT = Path(__file__).resolve().parents[1]
HELLO = ROOT / "tests" / "fixtures" / "hello.txt"


def _stable(report: dict) -> dict:
    cloned = json.loads(json.dumps(report))
    cloned.pop("system", None)
    source = cloned.get("source")
    if isinstance(source, dict):
        source.pop("path", None)
    temporal = cloned.get("temporal")
    if isinstance(temporal, dict):
        filesystem = temporal.get("filesystem")
        if isinstance(filesystem, dict):
            filesystem.pop("accessed", None)
    diagnostics = cloned.get("diagnostics")
    if isinstance(diagnostics, dict):
        diagnostics.pop("elapsed_ms", None)
        for run in diagnostics.get("extractors") or []:
            if isinstance(run, dict):
                run.pop("ms", None)
    return cloned


def test_hello_matches_the_rust_probe():
    report = extract(HELLO, hashes="none")
    probe = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(ROOT / "probes" / "rust_extract" / "Cargo.toml"),
            "--",
            str(HELLO),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    expected = json.loads(probe.stdout)
    assert _stable(report) == _stable(expected)
    assert report["whiff"]["schema"] == "whiff/1"
    assert report["source"]["name"] == "hello.txt"


def test_missing_path_and_bad_options(tmp_path):
    missing = tmp_path / "missing.txt"
    with pytest.raises(NotFoundError) as caught:
        extract(missing)
    assert caught.value.reason == "enoent"
    assert caught.value.path == str(missing)

    with pytest.raises(InvalidOptionError, match="turbo"):
        extract(HELLO, profile="turbo")
    with pytest.raises(InvalidOptionError, match="unknown option"):
        extract(HELLO, tokens=10)
    with pytest.raises(InvalidOptionError, match="tokens"):
        llm(HELLO, tokens=0)
    with pytest.raises(UnsupportedInputError):
        extract(123)  # type: ignore[arg-type]
    with pytest.raises(UnsupportedInputError):
        extract("a\0b")


def test_bytes_file_object_and_hashes(tmp_path):
    data = HELLO.read_bytes()
    named = extract(data, name="hello.txt", hashes=["sha256"])
    assert named["source"]["name"] == "hello.txt"
    assert "sha256" in named["integrity"]
    assert "blake3" not in named["integrity"]

    unnamed = extract(data, hashes="none")
    assert "sha256" not in unnamed.get("integrity", {})

    with HELLO.open("rb") as handle:
        from_file = extract(handle, hashes="none")
    assert from_file["identification"]["format"]

    broken = tmp_path / "bad.pdf"
    broken.write_bytes(b"%PDF-1.7\nnot a real pdf\n")
    report = extract(broken, hashes="none")
    assert report["whiff"]["schema"] == "whiff/1"
    assert "diagnostics" in report


def test_permission_denied(tmp_path):
    folder = tmp_path / "locked"
    folder.mkdir()
    path = folder / "secret.txt"
    path.write_text("hidden\n")
    folder.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("process can still read a mode-0 directory")
        with pytest.raises(AccessError) as caught:
            extract(path)
        assert caught.value.reason == "eacces"
    finally:
        folder.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def test_llm_view_and_version():
    view = llm(HELLO, tokens=200, hashes="none")
    assert isinstance(view, dict)
    assert view
    info = version()
    assert info["version"] == "0.1.0"
    assert info["crate"] == "0.8.0"
    assert info["schema"] == "whiff/1"
    assert "common" in info["features"]
    assert info["limit_caps"] == LIMIT_CAPS
    assert schema()["$defs"]["Severity"]


def test_directory_is_a_report(tmp_path):
    report = extract(tmp_path, hashes="none")
    assert report["whiff"]["schema"] == "whiff/1"
