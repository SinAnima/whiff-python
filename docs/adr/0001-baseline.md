# 0001 — Baseline and compatibility

**Status:** Accepted

**Upstream:** crates.io `whiff` **0.8.0** exactly (`default-features = false`, `features = ["common"]`)

## Pins

| Component | Version | Notes |
|---|---|---|
| Rust crate `whiff` | 0.8.0 | No `cli`. Specialist collections are cargo features, not the default wheel |
| Report schema | `whiff/1` | Vendored at `src/whiff/schemas/whiff-1.schema.json` |
| Rust MSRV | 1.89 | Matches upstream |
| Python | 3.11+ | Stable ABI (`abi3-py311`), one wheel per platform |
| PyO3 | 0.30 | `extension-module` is enabled by maturin, not by `cargo test` |

`whiff.version()` reports the binding version, the locked crate version, `whiff::SCHEMA`, `enabled_features()`, and the same limit caps the native parser enforces.

## Native boundary

`native/src/lib.rs` builds an `Engine` from a JSON options object (`deny_unknown_fields`) and returns UTF-8 JSON bytes. Python decodes that into a dict. Reports are not modelled as dataclasses: `format.*` and `metadata.*` are free-form, and `whiff/1` only grows.

`Profile`, `Hashes`, `Limits`, `Privacy`, `Error`, and `Report` are `#[non_exhaustive]`. Hashes are built with `Hashes::default()` / `Hashes::NONE`. `Error::Io` is matched with a wildcard arm. Limits start from `profile.limits()`.

The GIL is released for extraction. `bytes` inputs are copied once into `Arc<[u8]>`. Panics become `native_error`. A native `file_timeout` can abandon a Rust worker; Python cannot cancel it.

Python cannot register into the Rust `Registry`. Extra formats are Python extractors that patch the report after native extraction, never inside it and never for embedded children.

## Python surface

`extract` accepts a path, `bytes`, or a binary file object. Keyword options that a call does not use are rejected. Failures raise `WhiffError`. `NotFoundError` also subclasses `FileNotFoundError`; `AccessError` also subclasses `PermissionError`.

A process-wide FIFO semaphore (default 8 slots, 60s wait) bounds native calls. `stage="local"` copies a regular file into a private scratch directory before a slot is taken, then rewrites the report so it still names the original path.

## Features

Published builds enable `common` only. A source build of the other collections is `maturin develop --features full` (or `geo`, `science`, `data`, `cad`, `forensics`, `games`). `WHIFF_FEATURES` is not applied by Cargo on its own; the build script warns when it is set to something other than `common`.
