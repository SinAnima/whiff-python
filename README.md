# whiff

Python bindings for [whiff](https://github.com/baoulo/whiff). Point it at a file or at bytes and it returns one [`whiff/1`](https://github.com/baoulo/whiff/blob/main/docs/schema/whiff-1.schema.json) report: format, hashes, security and rights signals, content, and format-specific metadata.

Identification and extraction run in the Rust crate (0.8.0, the `common` feature set). Python extractors and analyzers can add fields afterwards. They do not run inside native extraction, and they do not run for embedded children.

```python
import whiff

report = whiff.extract("invoice.pdf")
report["identification"]["format"]  # "pdf"

report = whiff.extract(data, name="invoice.pdf", hashes=["sha256"])
view = whiff.llm("contract.pdf", tokens=800)
```

Empty optional fields are omitted. The vendored schema is `whiff.schema()`.

## Install

Import the package as `whiff`. The PyPI project `whiff` already belongs to an unrelated library, so this distribution is named `whiff-python`. A GitHub release tagged with the `version` in `pyproject.toml` (an optional `v` prefix is fine) publishes the wheels. From a checkout, with Rust 1.89 or later:

```sh
maturin develop
```

That builds the `common` formats. A source build of every collection is:

```sh
maturin develop --features full
```

`geo`, `science`, `data`, `cad`, `forensics`, and `games` are the individual cargo features. Wheels are built with `common` only.

## Extract

`extract` accepts a path, `bytes`, or a binary file object. A file object is read up to `max_read_bytes` and then treated as bytes. `name` (or `filename`, not both) drives extension detection for in-memory input.

Corrupt or partial files still return a report. Problems inside the file are listed in `diagnostics`. The call raises `WhiffError` when the path cannot be inspected or an option is invalid:

```python
try:
    report = whiff.extract(path)
except whiff.NotFoundError:
    ...
except whiff.AccessError:
    ...
except whiff.InvalidOptionError as err:
    print(err.message)
```

`NotFoundError` is also a `FileNotFoundError`. `AccessError` is also a `PermissionError`. IO messages include the full path.

`llm` returns upstream `Report::llm_view`. Python plugins do not run for it.

```python
results = whiff.extract_many(
    paths,
    max_concurrency=4,
    timeout=300_000,
    profile="minimal",
    hashes="none",
)
```

Results keep input order. With `on_error="collect"` (the default) each item is `(path, report)` or `(path, error)`. With `on_error="halt"` the first error is raised and `err.details["partial"]` holds the pairs completed before it. `timeout` is per path, in milliseconds. A timeout does not stop native work that has already started.

An `Engine` holds native options and is safe to share across threads:

```python
engine = whiff.Engine(profile="minimal", hashes="none")
engine.extract(path)
```

Native calls take a process-wide slot (default 8). A caller that waits longer than `native_wait_ms` (default 60000) raises `OverloadedError`. Change the limits with `whiff.configure(native_max_concurrency=4, native_wait_ms=10_000)`.

`stage="local"` copies a regular file into a private scratch directory before taking a slot, for slow or network filesystems. The copy is removed afterwards. The report still describes the original path. Times are second precision, and fields Python does not read (birth time, allocated size, owner names, ACLs, extended attributes) are omitted, with a `diagnostics.warnings` entry. Files larger than `scratch_max_bytes` (default 1 GiB) are rejected.

## Options

An option a function does not use is rejected.

| Option | Values | Default |
|---|---|---|
| `profile` | `minimal`, `standard`, `full`, `llm` | `standard` |
| `hashes` | `all`, `none`, or a list of `sha256` / `blake3` | `all` |
| `privacy` | `strict`, `off` | `strict` |
| `only` / `skip` | extractor ids or groups | none |
| `format` | format id to force | detect |
| `provenance` | record which extractor set each field | `False` |
| `limits` | dict of native limits; see below | profile limits |
| `stage` | `never`, `local` | `never` |
| `name` / `filename` / `mime` | strings (`bytes` and file objects) | none |
| `tokens` | 1..100000 | `800` (`llm` only) |
| `mode` | `fallback`, `augment`, `override` | `fallback` |
| `extractors` / `analyzers` | plugin classes or instances | none |
| `strict` | plugin failure raises | `False` |
| `plugin_timeout_ms` | 1..600000 | `5000` |
| `override_fields` | dotted paths, for example `["content.title"]` | `[]` |
| `max_concurrency` / `on_error` / `timeout` | `extract_many` | `4` / `collect` / `300000` |

`limits` keys: `max_read_bytes` and `max_decompressed_bytes` (1..4 GiB), `hash_max_bytes` (0..4 GiB), `max_parse_bytes` (0..256 MiB), `max_text_bytes` (0..64 MiB), `max_depth` (0..8), `max_children` (0..500), `file_timeout_ms` and `extractor_timeout_ms` (1..600000).

`privacy="strict"` reduces personal data in native structured fields to counts and scrubs plugin patches. Upstream redacts secrets either way. `privacy="off"` leaves plugin patches unchanged.

## Plugins

```python
class Trade(whiff.Extractor):
    id = "myapp.trade"
    version = 1

    def supports(self, source, report) -> bool:
        return source.extension == ".trade"

    def extract(self, source, report) -> dict:
        return {"format": {"myapp.trade": {"trade_id": "T-1001"}}}


report = whiff.extract("positions/2026-10-28.trade", extractors=[Trade])
```

An analyzer subclasses `whiff.Analyzer` and implements `analyze(report, source)`. Analyzers run after extractors. Their patches always merge in `augment` mode.

| Mode | When an extractor runs | Existing native values |
|---|---|---|
| `fallback` | native extraction did not cover a readable file | kept, except `content.*` |
| `augment` | `supports` returns true | kept |
| `override` | `supports` returns true | replaced for paths in `override_fields` |

`whiff`, `integrity`, and `embedded` cannot be patched. `diagnostics` accepts only extra warnings. `security.risks` are appended with `source` set to `python:<id>`. `metadata` and `format` keys are namespaces. One plugin cannot replace a value another plugin wrote unless that path is declared.

A failed plugin is recorded in `diagnostics.extractors` with `status` `error`, and the call still returns the report. With `strict=True` the call raises. Plugins run on a worker thread. They are not a security boundary.

`whiff.merge` applies the same rules to a patch dict.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
maturin develop
ruff check src tests
pytest
```

Golden reports are compared with `probes/rust_extract`, which links the same `whiff` 0.8.0 crate. Design notes: [docs/adr/0001-baseline.md](docs/adr/0001-baseline.md).

## Limitations

- `extract` of `bytes` copies the buffer once into native memory.
- There is no streaming reader. A file object is read up to the read cap.
- Python callbacks do not run for embedded children, and `llm` does not run them.
- `stage="local"` copies the whole file first.
- A native `file_timeout` can leave a Rust worker running after the call returns.
- IO error messages include the full path.

## License

MIT. Upstream whiff is also MIT.
