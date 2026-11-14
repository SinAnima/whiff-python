import threading

import pytest

from whiff import NotFoundError, OverloadedError, configure, extract, extract_many
from whiff.limiter import LIMITER

HELLO_NAME = "hello.txt"


def test_extract_many_keeps_order(tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("one\n")
    second.write_text("two\n")
    missing = tmp_path / "missing.txt"
    results = extract_many([first, missing, second], hashes="none", max_concurrency=2)
    assert [path for path, _item in results] == [str(first), str(missing), str(second)]
    assert results[0][1]["source"]["name"] == "a.txt"
    assert isinstance(results[1][1], NotFoundError)
    assert results[2][1]["source"]["name"] == "b.txt"


def test_halt_includes_partial(tmp_path):
    ok = tmp_path / "ok.txt"
    ok.write_text("ok\n")
    missing = tmp_path / "missing.txt"
    with pytest.raises(NotFoundError) as caught:
        extract_many([ok, missing], hashes="none", on_error="halt", max_concurrency=1)
    partial = caught.value.details["partial"]
    assert len(partial) == 1
    assert partial[0][1]["source"]["name"] == "ok.txt"


def test_paths_must_be_a_list():
    from whiff import UnsupportedInputError

    with pytest.raises(UnsupportedInputError):
        extract_many("nope")  # type: ignore[arg-type]


def test_overloaded_when_the_slot_does_not_free(tmp_path):
    path = tmp_path / HELLO_NAME
    path.write_text("hello\n")
    configure(native_max_concurrency=1, native_wait_ms=50)
    started = threading.Event()
    release = threading.Event()

    def hold():
        with LIMITER.slot():
            started.set()
            release.wait(2)

    worker = threading.Thread(target=hold)
    worker.start()
    assert started.wait(2)
    try:
        with pytest.raises(OverloadedError):
            extract(path, hashes="none")
    finally:
        release.set()
        worker.join(2)
        configure(native_max_concurrency=8, native_wait_ms=60_000)
