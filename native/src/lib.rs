//! PyO3 boundary for the Python `whiff` package.
//!
//! Returns UTF-8 JSON bytes. Python decodes them into dicts. Extraction runs
//! with the GIL released. Panics become `NativeFault` rather than aborting the
//! interpreter.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Deserialize;
use serde_json::{Map, Value};
use whiff::{Engine, Error as WhiffError, Hashes, Limits, Privacy, Profile};

pyo3::create_exception!(_native, NativeFault, PyException);

/// Upper caps for user-supplied limits. `whiff.options` mirrors these values;
/// a test compares both through `version()`.
const LIMIT_CAPS: &[(&str, u64)] = &[
    ("max_read_bytes", 4 * 1024 * 1024 * 1024),
    ("max_decompressed_bytes", 4 * 1024 * 1024 * 1024),
    ("max_depth", 8),
    ("max_children", 500),
    ("file_timeout_ms", 600_000),
    ("extractor_timeout_ms", 600_000),
    ("max_text_bytes", 64 * 1024 * 1024),
    ("hash_max_bytes", 4 * 1024 * 1024 * 1024),
    ("max_parse_bytes", 256 * 1024 * 1024),
];

/// Limits where zero has no useful meaning upstream and is rejected.
const NONZERO_LIMITS: &[&str] = &[
    "max_read_bytes",
    "max_decompressed_bytes",
    "file_timeout_ms",
    "extractor_timeout_ms",
];

const DEFAULT_TOKENS: usize = 800;
const MAX_TOKENS: usize = 100_000;

#[derive(Debug)]
struct Fault {
    reason: &'static str,
    message: String,
}

impl Fault {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            reason: "invalid_option",
            message: message.into(),
        }
    }

    fn native(message: impl Into<String>) -> Self {
        Self {
            reason: "native_error",
            message: message.into(),
        }
    }

    fn into_py(self) -> PyErr {
        PyErr::new::<NativeFault, _>((self.reason, self.message))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeOptions {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    hashes: Option<HashesOpt>,
    #[serde(default)]
    privacy: Option<String>,
    #[serde(default)]
    only: Option<Vec<String>>,
    #[serde(default)]
    skip: Option<Vec<String>>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    provenance: Option<bool>,
    #[serde(default)]
    limits: Option<LimitsOpt>,
    #[serde(default)]
    tokens: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum HashesOpt {
    Named(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsOpt {
    max_read_bytes: Option<u64>,
    max_decompressed_bytes: Option<u64>,
    max_depth: Option<u32>,
    max_children: Option<u32>,
    file_timeout_ms: Option<u64>,
    extractor_timeout_ms: Option<u64>,
    max_text_bytes: Option<u64>,
    hash_max_bytes: Option<u64>,
    max_parse_bytes: Option<u64>,
}

fn parse_options(json: &str) -> Result<NativeOptions, Fault> {
    if json.trim().is_empty() {
        return Ok(NativeOptions::default());
    }
    serde_json::from_str(json).map_err(|err| Fault::invalid(format!("invalid options json: {err}")))
}

fn hashes_from(opt: &HashesOpt) -> Result<Hashes, Fault> {
    match opt {
        // Hashes is #[non_exhaustive] since whiff 0.8: use constructors.
        HashesOpt::Named(name) => match name.as_str() {
            "all" => Ok(Hashes::default()),
            "none" => Ok(Hashes::NONE),
            other => Err(Fault::invalid(format!("invalid hashes `{other}`"))),
        },
        HashesOpt::List(list) => {
            let mut hashes = Hashes::NONE;
            for item in list {
                match item.as_str() {
                    "sha256" => hashes.sha256 = true,
                    "blake3" => hashes.blake3 = true,
                    other => return Err(Fault::invalid(format!("invalid hash `{other}`"))),
                }
            }
            Ok(hashes)
        }
    }
}

fn checked(name: &str, value: u64) -> Result<u64, Fault> {
    if value == 0 && NONZERO_LIMITS.contains(&name) {
        return Err(Fault::invalid(format!("{name} must be greater than 0")));
    }
    let cap = LIMIT_CAPS
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, cap)| *cap)
        .unwrap_or(u64::MAX);
    if value > cap {
        return Err(Fault::invalid(format!("{name} exceeds cap {cap}")));
    }
    Ok(value)
}

fn checked_u32(name: &str, value: u32) -> Result<u32, Fault> {
    checked(name, u64::from(value)).map(|_| value)
}

fn apply_limits(mut base: Limits, opt: &LimitsOpt) -> Result<Limits, Fault> {
    if let Some(n) = opt.max_read_bytes {
        base.max_read_bytes = checked("max_read_bytes", n)?;
    }
    if let Some(n) = opt.max_decompressed_bytes {
        base.max_decompressed_bytes = checked("max_decompressed_bytes", n)?;
    }
    if let Some(n) = opt.max_depth {
        base.max_depth = checked_u32("max_depth", n)?;
    }
    if let Some(n) = opt.max_children {
        base.max_children = checked_u32("max_children", n)?;
    }
    if let Some(ms) = opt.file_timeout_ms {
        base.file_timeout = Some(Duration::from_millis(checked("file_timeout_ms", ms)?));
    }
    if let Some(ms) = opt.extractor_timeout_ms {
        base.extractor_timeout = Some(Duration::from_millis(checked("extractor_timeout_ms", ms)?));
    }
    if let Some(n) = opt.max_text_bytes {
        let n = checked("max_text_bytes", n)?;
        base.max_text_bytes =
            usize::try_from(n).map_err(|_| Fault::invalid("max_text_bytes too large"))?;
    }
    if let Some(n) = opt.hash_max_bytes {
        base.hash_max_bytes = checked("hash_max_bytes", n)?;
    }
    if let Some(n) = opt.max_parse_bytes {
        base.max_parse_bytes = checked("max_parse_bytes", n)?;
    }
    Ok(base)
}

fn parse_profile(name: &str) -> Result<Profile, Fault> {
    name.parse().map_err(|err: String| Fault::invalid(err))
}

fn build_engine(opts: &NativeOptions) -> Result<Engine, Fault> {
    // `tokens` is per call, not an engine setting. Reject an out-of-range
    // value here so a payload that includes it still fails closed.
    if opts.tokens.is_some() {
        tokens_from(opts.tokens)?;
    }

    let profile = opts.profile.as_deref().map(parse_profile).transpose()?;

    let mut builder = Engine::builder();
    if let Some(profile) = profile {
        builder = builder.profile(profile);
    }
    if let Some(ref hashes) = opts.hashes {
        builder = builder.hashes(hashes_from(hashes)?);
    }
    if let Some(ref privacy) = opts.privacy {
        let privacy: Privacy = privacy.parse().map_err(|err: String| Fault::invalid(err))?;
        builder = builder.privacy(privacy);
    }
    if let Some(ref only) = opts.only {
        builder = builder.only(only.clone());
    }
    if let Some(ref skip) = opts.skip {
        builder = builder.skip(skip.clone());
    }
    if let Some(ref format) = opts.format {
        builder = builder.format(format.clone());
    }
    if let Some(provenance) = opts.provenance {
        builder = builder.provenance(provenance);
    }
    if let Some(ref limits) = opts.limits {
        // Setting a profile resets limits, so start from the profile's limits.
        let base = profile.unwrap_or_default().limits();
        builder = builder.limits(apply_limits(base, limits)?);
    }
    Ok(builder.build())
}

fn tokens_from(tokens: Option<u64>) -> Result<usize, Fault> {
    let tokens = tokens.unwrap_or(DEFAULT_TOKENS as u64);
    if tokens == 0 || tokens > MAX_TOKENS as u64 {
        return Err(Fault::invalid(format!("tokens must be 1..{MAX_TOKENS}")));
    }
    usize::try_from(tokens).map_err(|_| Fault::invalid("tokens too large"))
}

/// Build a filesystem path from raw bytes. Unix paths are arbitrary bytes;
/// Windows paths must be valid UTF-8.
fn path_from_bytes(bytes: &[u8]) -> Result<PathBuf, Fault> {
    if bytes.is_empty() {
        return Err(Fault {
            reason: "unsupported_input",
            message: "path must not be empty".into(),
        });
    }
    if bytes.contains(&0) {
        return Err(Fault {
            reason: "unsupported_input",
            message: "path must not contain NUL bytes".into(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| Fault {
                reason: "unsupported_input",
                message: "path is not valid UTF-8".into(),
            })
    }
}

fn io_error(err: WhiffError) -> Fault {
    match err {
        WhiffError::Io { path, source } => {
            let reason = match source.kind() {
                std::io::ErrorKind::NotFound => "enoent",
                std::io::ErrorKind::PermissionDenied => "eacces",
                _ => "native_error",
            };
            Fault {
                reason,
                message: format!("{}: {source}", path.display()),
            }
        }
        // Error is #[non_exhaustive] since whiff 0.8.
        other => Fault::native(other.to_string()),
    }
}

fn to_json(value: &impl serde::Serialize) -> Result<Vec<u8>, Fault> {
    serde_json::to_vec(value).map_err(|err| Fault {
        reason: "invalid_report",
        message: format!("serialize failed: {err}"),
    })
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn call_native<T>(py: Python<'_>, work: impl FnOnce() -> Result<T, Fault> + Send) -> PyResult<T>
where
    T: Send,
{
    let outcome = py.detach(move || catch_unwind(AssertUnwindSafe(work)));
    match outcome {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(fault)) => Err(fault.into_py()),
        Err(payload) => Err(Fault::native(format!(
            "native panic: {}",
            panic_message(payload.as_ref())
        ))
        .into_py()),
    }
}

fn bytes_out(py: Python<'_>, bytes: Vec<u8>) -> PyResult<Py<PyBytes>> {
    Ok(PyBytes::new(py, &bytes).unbind())
}

fn limits_json(limits: &Limits) -> Value {
    let mut map = Map::new();
    map.insert("max_read_bytes".into(), Value::from(limits.max_read_bytes));
    map.insert(
        "max_decompressed_bytes".into(),
        Value::from(limits.max_decompressed_bytes),
    );
    map.insert("max_depth".into(), Value::from(limits.max_depth));
    map.insert("max_children".into(), Value::from(limits.max_children));
    map.insert(
        "file_timeout_ms".into(),
        match limits.file_timeout {
            Some(duration) => Value::from(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
            None => Value::Null,
        },
    );
    map.insert(
        "extractor_timeout_ms".into(),
        match limits.extractor_timeout {
            Some(duration) => Value::from(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
            None => Value::Null,
        },
    );
    map.insert(
        "max_text_bytes".into(),
        Value::from(limits.max_text_bytes as u64),
    );
    map.insert("hash_max_bytes".into(), Value::from(limits.hash_max_bytes));
    map.insert(
        "max_parse_bytes".into(),
        Value::from(limits.max_parse_bytes),
    );
    Value::Object(map)
}

fn version_map() -> Value {
    let mut caps = Map::new();
    for (key, cap) in LIMIT_CAPS {
        caps.insert((*key).into(), Value::from(*cap));
    }
    let mut map = Map::new();
    map.insert(
        "version".into(),
        Value::String(env!("CARGO_PKG_VERSION").into()),
    );
    map.insert(
        "crate".into(),
        Value::String(env!("WHIFF_CRATE_VERSION").into()),
    );
    map.insert("schema".into(), Value::String(whiff::SCHEMA.into()));
    map.insert(
        "features".into(),
        Value::Array(
            whiff::enabled_features()
                .into_iter()
                .map(|feature| Value::String(feature.into()))
                .collect(),
        ),
    );
    map.insert("limit_caps".into(), Value::Object(caps));
    Value::Object(map)
}

/// Shared native engine. Frozen so threads can extract concurrently.
#[pyclass(frozen, name = "Engine")]
struct NativeEngine {
    inner: Engine,
}

#[pymethods]
impl NativeEngine {
    #[new]
    fn new(options_json: &str) -> PyResult<Self> {
        let opts = parse_options(options_json).map_err(Fault::into_py)?;
        let inner = build_engine(&opts).map_err(Fault::into_py)?;
        Ok(Self { inner })
    }

    fn extract_path(&self, py: Python<'_>, path: &[u8]) -> PyResult<Py<PyBytes>> {
        let engine = self.inner.clone();
        let path = path_from_bytes(path).map_err(Fault::into_py)?;
        let bytes = call_native(py, move || {
            let report = engine.extract_path(&path).map_err(io_error)?;
            to_json(&report)
        })?;
        bytes_out(py, bytes)
    }

    fn extract_bytes(
        &self,
        py: Python<'_>,
        data: &[u8],
        name: Option<&str>,
    ) -> PyResult<Py<PyBytes>> {
        let engine = self.inner.clone();
        let name = name.map(str::to_owned);
        // Copy once into Arc<[u8]> inside the detached call.
        let data = data.to_vec();
        let bytes = call_native(py, move || {
            let bytes: Arc<[u8]> = Arc::from(data.into_boxed_slice());
            to_json(&engine.extract_bytes(name.as_deref(), bytes))
        })?;
        bytes_out(py, bytes)
    }

    fn llm_path(&self, py: Python<'_>, path: &[u8], tokens: u64) -> PyResult<Py<PyBytes>> {
        let engine = self.inner.clone();
        let path = path_from_bytes(path).map_err(Fault::into_py)?;
        let tokens = tokens_from(Some(tokens)).map_err(Fault::into_py)?;
        let bytes = call_native(py, move || {
            let report = engine.extract_path(&path).map_err(io_error)?;
            to_json(&report.llm_view(tokens))
        })?;
        bytes_out(py, bytes)
    }

    fn llm_bytes(
        &self,
        py: Python<'_>,
        data: &[u8],
        name: Option<&str>,
        tokens: u64,
    ) -> PyResult<Py<PyBytes>> {
        let engine = self.inner.clone();
        let name = name.map(str::to_owned);
        let data = data.to_vec();
        let tokens = tokens_from(Some(tokens)).map_err(Fault::into_py)?;
        let bytes = call_native(py, move || {
            let bytes: Arc<[u8]> = Arc::from(data.into_boxed_slice());
            let report = engine.extract_bytes(name.as_deref(), bytes);
            to_json(&report.llm_view(tokens))
        })?;
        bytes_out(py, bytes)
    }
}

#[pyfunction]
fn version(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    bytes_out(py, to_json(&version_map()).map_err(Fault::into_py)?)
}

#[pyfunction]
fn default_limits(py: Python<'_>, profile: Option<&str>) -> PyResult<Py<PyBytes>> {
    let profile = match profile {
        Some(name) => parse_profile(name).map_err(Fault::into_py)?,
        None => Profile::default(),
    };
    bytes_out(
        py,
        to_json(&limits_json(&profile.limits())).map_err(Fault::into_py)?,
    )
}

#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeEngine>()?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(default_limits, m)?)?;
    m.add("NativeFault", py.get_type::<NativeFault>())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_options_parse_to_defaults() {
        let opts = parse_options("").expect("defaults");
        assert!(opts.profile.is_none());
        assert!(build_engine(&opts).is_ok());
    }

    #[test]
    fn unknown_option_keys_are_rejected() {
        assert!(parse_options(r#"{"nope": 1}"#).is_err());
        assert!(parse_options(r#"{"limits": {"nope": 1}}"#).is_err());
    }

    #[test]
    fn hashes_named_and_list() {
        let none = hashes_from(&HashesOpt::Named("none".into())).expect("none");
        assert!(!none.sha256 && !none.blake3);
        let list = hashes_from(&HashesOpt::List(vec!["sha256".into()])).expect("list");
        assert!(list.sha256 && !list.blake3);
        assert!(hashes_from(&HashesOpt::Named("md5".into())).is_err());
        assert!(hashes_from(&HashesOpt::List(vec!["md5".into()])).is_err());
    }

    #[test]
    fn limits_respect_caps_and_nonzero_rules() {
        let base = Profile::default().limits();
        let ok = LimitsOpt {
            max_depth: Some(0),
            hash_max_bytes: Some(0),
            ..Default::default()
        };
        assert!(apply_limits(base.clone(), &ok).is_ok());

        let zero_timeout = LimitsOpt {
            file_timeout_ms: Some(0),
            ..Default::default()
        };
        assert!(apply_limits(base.clone(), &zero_timeout).is_err());

        let over = LimitsOpt {
            max_parse_bytes: Some(u64::MAX),
            ..Default::default()
        };
        assert!(apply_limits(base, &over).is_err());
    }

    #[test]
    fn invalid_profile_and_privacy_are_errors() {
        let bad_profile = parse_options(r#"{"profile": "turbo"}"#).expect("parse");
        assert!(build_engine(&bad_profile).is_err());
        let bad_privacy = parse_options(r#"{"privacy": "maybe"}"#).expect("parse");
        assert!(build_engine(&bad_privacy).is_err());
    }

    #[test]
    fn tokens_bounds() {
        assert!(tokens_from(Some(0)).is_err());
        assert_eq!(tokens_from(Some(200)).expect("tokens"), 200);
        assert_eq!(tokens_from(None).expect("default"), DEFAULT_TOKENS);
        assert!(tokens_from(Some(MAX_TOKENS as u64 + 1)).is_err());
    }

    #[test]
    fn path_bytes_validation() {
        assert!(path_from_bytes(b"").is_err());
        assert!(path_from_bytes(b"a\0b").is_err());
        assert!(path_from_bytes(b"plain.txt").is_ok());
        #[cfg(unix)]
        assert!(path_from_bytes(&[b'x', 0xFF]).is_ok());
    }

    #[test]
    fn panic_payloads_are_described() {
        let payload = catch_unwind(|| panic!("boom")).expect_err("panics");
        assert_eq!(panic_message(payload.as_ref()), "boom");
    }

    #[test]
    fn version_info_reports_locked_crate_version() {
        let info = version_map();
        assert_eq!(info["crate"], "0.8.0");
        assert_eq!(info["schema"], whiff::SCHEMA);
        assert_eq!(info["limit_caps"]["max_depth"], 8);
        let features = info["features"].as_array().expect("features");
        assert!(features.iter().any(|feature| feature == "common"));
    }
}
