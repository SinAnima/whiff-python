import pytest

from whiff import ConflictError, InvalidReportError, merge
from whiff.report import native_covered


def test_augment_keeps_native_title_and_adds_fields():
    base = {"content": {"title": "native"}, "metadata": {}}
    patch = {
        "content": {"title": "plugin", "extra": 1},
        "metadata": {"myapp.x": {"v": 1}},
    }
    merged = merge(base, patch, mode="augment")
    assert merged["content"]["title"] == "native"
    assert merged["content"]["extra"] == 1
    assert merged["metadata"]["myapp.x"] == {"v": 1}


def test_fallback_replaces_content_scalar():
    merged = merge(
        {"content": {"title": "n"}},
        {"content": {"title": "p"}},
        mode="fallback",
    )
    assert merged["content"]["title"] == "p"


def test_override_requires_a_declared_path():
    base = {"metadata": {"native.key": 1}}
    merged = merge(
        base,
        {"metadata": {"native.key": 2}},
        mode="override",
        override_fields=["metadata.native.key"],
    )
    assert merged["metadata"]["native.key"] == 2
    with pytest.raises(ConflictError):
        merge(base, {"metadata": {"native.key": 2}}, mode="override")


def test_risks_are_appended_with_a_python_source():
    merged = merge(
        {"security": {"risks": []}},
        {
            "security": {
                "risks": [{"kind": "macros", "category": "active_content", "severity": "high"}]
            }
        },
        plugin_id="myapp.scan",
    )
    assert merged["security"]["risks"][0]["source"] == "python:myapp.scan"


def test_protected_and_unknown_sections():
    with pytest.raises(InvalidReportError, match="embedded"):
        merge({}, {"embedded": {}})
    with pytest.raises(ConflictError, match="whiff"):
        merge({"whiff": {"schema": "whiff/1"}}, {"whiff": {}})
    with pytest.raises(InvalidReportError, match="plugins"):
        merge({}, {"plugins": {}})
    with pytest.raises(InvalidReportError, match="dict"):
        merge("nope", {})  # type: ignore[arg-type]


def test_keywords_are_appended_once():
    merged = merge(
        {"content": {"keywords": ["a"]}},
        {"content": {"keywords": ["a", "b"]}},
        mode="augment",
    )
    assert merged["content"]["keywords"] == ["a", "b"]


def test_second_plugin_cannot_replace_an_owned_path():
    from whiff.merge import merge_tracked

    report, written = merge_tracked({}, {"content": {"title": "one"}}, plugin_id="a")
    with pytest.raises(ConflictError, match="another plugin"):
        merge_tracked(
            report,
            {"content": {"title": "two"}},
            plugin_id="b",
            owned=set(written),
        )


def test_native_covered_requires_extension_and_ok_extractor():
    assert native_covered({}) is False
    assert native_covered(
        {
            "identification": {
                "extractor": "text.plain",
                "extension_matches": True,
                "detected_by": "extension",
            },
            "diagnostics": {"extractors": [{"id": "text.plain", "status": "ok"}]},
        }
    )
    assert (
        native_covered(
            {
                "identification": {"extractor": "text.plain", "detected_by": "heuristic"},
                "diagnostics": {"extractors": [{"id": "text.plain", "status": "ok"}]},
            }
        )
        is False
    )
