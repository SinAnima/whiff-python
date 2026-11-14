from whiff import extract


def test_stage_local_keeps_the_original_path(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("staged hello\n")
    report = extract(path, hashes="none", stage="local")
    assert report["source"]["path"] == str(path)
    assert report["source"]["name"] == "notes.txt"
    warnings = report["diagnostics"]["warnings"]
    assert any("stage=" in warning and "omitted" in warning for warning in warnings)
    assert "created" not in report.get("temporal", {}).get("filesystem", {})
