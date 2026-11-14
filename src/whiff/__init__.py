"""Identify a file or bytes and return a whiff/1 report.

The report is the JSON document produced by the Rust `whiff` crate: what the
file is, where it came from, which rights apply, and a compact view of its
content. This package wraps that crate. It does not reimplement format
extractors.
"""

from whiff.engine import (
    Engine,
    __version__,
    configure,
    extract,
    extract_many,
    llm,
    schema,
    version,
)
from whiff.errors import (
    AccessError,
    AnalyzerError,
    ConflictError,
    ExtractorError,
    InvalidOptionError,
    InvalidReportError,
    NativeError,
    NotFoundError,
    OverloadedError,
    UnsupportedInputError,
    WhiffError,
    WhiffTimeoutError,
)
from whiff.input import Input
from whiff.merge import merge
from whiff.plugins import Analyzer, Extractor
from whiff.report import native_covered

__all__ = [
    "AccessError",
    "Analyzer",
    "AnalyzerError",
    "ConflictError",
    "Engine",
    "Extractor",
    "ExtractorError",
    "Input",
    "InvalidOptionError",
    "InvalidReportError",
    "NativeError",
    "NotFoundError",
    "OverloadedError",
    "UnsupportedInputError",
    "WhiffError",
    "WhiffTimeoutError",
    "__version__",
    "configure",
    "extract",
    "extract_many",
    "llm",
    "merge",
    "native_covered",
    "schema",
    "version",
]
