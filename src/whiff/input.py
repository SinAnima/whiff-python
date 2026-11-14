"""Description of one extraction input passed to Python plugins."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Input:
    """Path or in-memory payload. ``bytes`` is omitted from :meth:`present`."""

    source: str
    path: str | None = None
    data: bytes | None = None
    filename: str | None = None
    extension: str | None = None
    mime: str | None = None
    size: int | None = None

    def present(self) -> dict[str, object]:
        return {
            "source": self.source,
            "path": self.path,
            "filename": self.filename,
            "extension": self.extension,
            "mime": self.mime,
            "size": self.size,
        }


def from_path(path: str) -> Input:
    filename = os.path.basename(path)
    size: int | None
    try:
        size = os.stat(path).st_size
    except OSError:
        size = None
    return Input(
        source="path",
        path=path,
        filename=filename,
        extension=_extension(filename),
        size=size,
    )


def from_binary(data: bytes, *, name: str | None = None, mime: str | None = None) -> Input:
    filename = name or "input.bin"
    return Input(
        source="binary",
        data=data,
        filename=filename,
        extension=_extension(filename),
        mime=mime,
        size=len(data),
    )


def _extension(filename: str) -> str | None:
    ext = Path(filename).suffix
    if not ext:
        return None
    return ext.lower()
