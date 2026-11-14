import time

import pytest

from whiff import ConflictError, Extractor, extract
from whiff.input import Input
from whiff.plugins import run


class Trade(Extractor):
    id = "myapp.trade"
    version = 1

    def supports(self, source: Input, report: dict) -> bool:
        return source.extension == ".trade"

    def extract(self, source: Input, report: dict) -> dict:
        return {
            "content": {"title": "Trade"},
            "format": {"myapp.trade": {"ok": True}},
        }


class Title(Extractor):
    id = "myapp.title"
    version = 1

    def supports(self, source, report) -> bool:
        return True

    def extract(self, source, report) -> dict:
        return {"content": {"title": "plugin", "extra": 1}}


class Boom(Extractor):
    id = "myapp.boom"
    version = 1

    def supports(self, source, report) -> bool:
        return True

    def extract(self, source, report) -> dict:
        raise RuntimeError("secret contents")


class Slow(Extractor):
    id = "myapp.slow"
    version = 1

    def supports(self, source, report) -> bool:
        return True

    def extract(self, source, report) -> dict:
        time.sleep(1.5)
        return {"content": {"note": "late"}}


def _base(**identification):
    ident = {"format": "text", "extractor": "text.plain", "extension_matches": True}
    ident.update(identification)
    return {
        "identification": ident,
        "content": {"title": "native"},
        "metadata": {},
        "format": {},
        "diagnostics": {"extractors": [{"id": "text.plain", "status": "ok"}]},
    }


def test_fallback_runs_when_native_did_not_cover(tmp_path):
    path = tmp_path / "pos.trade"
    path.write_text("TRADE/1\n")
    report = extract(path, hashes="none", extractors=[Trade])
    assert report["format"]["myapp.trade"] == {"ok": True}
    assert report["content"]["title"] == "Trade"
    assert report["diagnostics"]["extractors"][-1]["status"] == "ok"


def test_augment_keeps_an_existing_title():
    source = Input(source="binary", data=b"hello\n", filename="notes.txt", extension=".txt", size=6)
    report = run(
        source,
        _base(),
        {
            "mode": "augment",
            "strict": False,
            "privacy": "off",
            "plugin_timeout_ms": 5000,
            "provenance": False,
            "override_fields": [],
            "extractors": [Title],
            "analyzers": [],
        },
    )
    assert report["content"]["title"] == "native"
    assert report["content"]["extra"] == 1


def test_override_conflict_is_strict():
    source = Input(source="binary", data=b"hello\n", filename="notes.txt", extension=".txt", size=6)
    with pytest.raises(ConflictError):
        run(
            source,
            _base(),
            {
                "mode": "override",
                "strict": True,
                "privacy": "off",
                "plugin_timeout_ms": 5000,
                "provenance": False,
                "override_fields": [],
                "extractors": [Title],
                "analyzers": [],
            },
        )


def test_plugin_error_is_recorded_and_not_the_exception_text():
    source = Input(source="binary", data=b"x", filename="x.txt", extension=".txt", size=1)
    report = run(
        source,
        _base(),
        {
            "mode": "augment",
            "strict": False,
            "privacy": "strict",
            "plugin_timeout_ms": 5000,
            "provenance": False,
            "override_fields": [],
            "extractors": [Boom],
            "analyzers": [],
        },
    )
    last = report["diagnostics"]["extractors"][-1]
    assert last["status"] == "error"
    assert "secret" not in last["error"]
    assert "RuntimeError" in last["error"]


def test_plugin_timeout(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("hello\n")
    report = extract(
        path,
        hashes="none",
        extractors=[Slow],
        mode="augment",
        plugin_timeout_ms=200,
    )
    last = report["diagnostics"]["extractors"][-1]
    assert last["status"] == "error"
    assert last["error_kind"] == "timeout"
