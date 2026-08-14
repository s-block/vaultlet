use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyMapping, PyModule, PyString,
};
use zeroize::Zeroize;

use crate::backend::RedisConfig;
use crate::crypto::{MasterKey, TenantCryptoContext};
use crate::error::{
    BackendError, ClosedError, ConfigurationError, Error, IntegrityError, InvalidKeyError,
    SerializationError, StoreLockedError, TypeMismatchError, UnsupportedFormatError, VaultletError,
};
use crate::format::{
    JSON_CODEC_VERSION, MAX_VALUE_SIZE, PlaintextBuffer, RECORD_PREFIX_SIZE, ValueKind,
};
use crate::json::{JsonArray, JsonArrayIterator, JsonDocument, JsonObject, JsonObjectIterator};
use crate::service::{
    Entry, MAX_BATCH_ITEMS, MAX_BATCH_VALUE_BYTES, MAX_KEY_LIST_LIMIT, Service, SetItem,
    StorageEngine,
};

const MAX_JSON_DEPTH: usize = 128;

struct ActiveContainers {
    identities: [usize; MAX_JSON_DEPTH + 1],
    len: usize,
}

impl ActiveContainers {
    fn new() -> Self {
        Self {
            identities: [0; MAX_JSON_DEPTH + 1],
            len: 0,
        }
    }

    fn enter(&mut self, identity: usize) -> Result<(), Error> {
        if self.identities[..self.len].contains(&identity) {
            return Err(Error::Serialization);
        }
        let destination = self
            .identities
            .get_mut(self.len)
            .ok_or(Error::Serialization)?;
        *destination = identity;
        self.len += 1;
        Ok(())
    }

    fn leave(&mut self) -> Result<(), Error> {
        self.len = self.len.checked_sub(1).ok_or(Error::Serialization)?;
        Ok(())
    }
}

#[pyclass(name = "_NativeMasterKey", module = "vaultlet._vaultlet", frozen)]
pub(crate) struct NativeMasterKey {
    key: MasterKey,
}

#[pymethods]
impl NativeMasterKey {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        MasterKey::generate()
            .map(|key| Self { key })
            .map_err(Error::into_pyerr)
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut value = copy_key_buffer(py, value)?;
        let result = MasterKey::from_slice(&value)
            .map(|key| Self { key })
            .map_err(Error::into_pyerr);
        value.zeroize();
        result
    }

    #[staticmethod]
    fn from_base64(value: &str) -> PyResult<Self> {
        MasterKey::from_base64(value)
            .map(|key| Self { key })
            .map_err(Error::into_pyerr)
    }

    fn export_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.key.expose())
    }

    fn export_base64(&self) -> String {
        self.key.to_base64()
    }

    fn __repr__(&self) -> &'static str {
        "MasterKey(<redacted>)"
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("MasterKey objects cannot be pickled"))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        self.__reduce__()
    }
}

#[pyclass(name = "_NativeStore", module = "vaultlet._vaultlet", frozen)]
pub(crate) struct NativeStore {
    service: Arc<Service>,
}

#[pymethods]
impl NativeStore {
    #[getter]
    fn closed(&self) -> bool {
        self.service.is_closed()
    }

    fn tenant(&self, tenant_id: &str) -> PyResult<NativeTenant> {
        let crypto = self.service.tenant(tenant_id).map_err(Error::into_pyerr)?;
        Ok(NativeTenant {
            service: Arc::clone(&self.service),
            crypto,
        })
    }

    fn rotate_master_key<'py>(
        &self,
        py: Python<'py>,
        key: PyRef<'_, NativeMasterKey>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let key = key.key.copy();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .rotate_master_key(key)
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn purge_expired<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service.purge_expired().await.map_err(Error::into_pyerr)
        })
    }

    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service.close().await.map_err(Error::into_pyerr)
        })
    }
}

#[pyclass(name = "_NativeTenant", module = "vaultlet._vaultlet", frozen)]
pub(crate) struct NativeTenant {
    service: Arc<Service>,
    crypto: Arc<TenantCryptoContext>,
}

#[pymethods]
impl NativeTenant {
    fn set<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: &Bound<'_, PyAny>,
        expires_at_ms: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = copy_buffer(py, value)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .set(
                    tenant,
                    SetItem {
                        key,
                        value,
                        kind: ValueKind::Bytes,
                        expires_at_ms,
                    },
                )
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn get<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = service
                .get(tenant, key, ValueKind::Bytes)
                .await
                .map_err(Error::into_pyerr)?;
            Python::attach(|py| Ok(value.map(|entry| PyBytes::new(py, entry.value()).unbind())))
        })
    }

    fn set_many<'py>(
        &self,
        py: Python<'py>,
        values: &Bound<'_, PyAny>,
        expires_at_ms: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let items = byte_mapping(py, values, expires_at_ms)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .set_many(tenant, items)
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn get_many<'py>(
        &self,
        py: Python<'py>,
        keys: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let keys = string_iterable(keys)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (keys, entries) = service
                .get_many(tenant, keys, Some(ValueKind::Bytes))
                .await
                .map_err(Error::into_pyerr)?;
            Python::attach(|py| byte_result_dict(py, keys, entries))
        })
    }

    fn set_json<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: &Bound<'_, PyAny>,
        expires_at_ms: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = encode_json(value)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .set(
                    tenant,
                    SetItem {
                        key,
                        value,
                        kind: ValueKind::Json,
                        expires_at_ms,
                    },
                )
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn get_json<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let document = service
                .get_json(tenant, key)
                .await
                .map_err(Error::into_pyerr)?;
            Python::attach(|py| document.map(|document| document.into_py(py)).transpose())
        })
    }

    fn set_many_json<'py>(
        &self,
        py: Python<'py>,
        values: &Bound<'_, PyAny>,
        expires_at_ms: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let items = json_mapping(values, expires_at_ms)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .set_many(tenant, items)
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn get_many_json<'py>(
        &self,
        py: Python<'py>,
        keys: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let keys = string_iterable(keys)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (keys, documents) = service
                .get_many_json(tenant, keys)
                .await
                .map_err(Error::into_pyerr)?;
            Python::attach(|py| json_result_dict(py, keys, documents))
        })
    }

    fn delete<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service.delete(tenant, key).await.map_err(Error::into_pyerr)
        })
    }

    fn delete_many<'py>(
        &self,
        py: Python<'py>,
        keys: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let keys = string_iterable(keys)?;
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .delete_many(tenant, keys)
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn exists<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service.exists(tenant, key).await.map_err(Error::into_pyerr)
        })
    }

    fn metadata<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .metadata(tenant, key)
                .await
                .map(|value| {
                    value.map(|value| (value.kind as u8, value.encoded_size, value.expires_at_ms))
                })
                .map_err(Error::into_pyerr)
        })
    }

    fn keys<'py>(
        &self,
        py: Python<'py>,
        limit: usize,
        cursor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let service = Arc::clone(&self.service);
        let tenant = Arc::clone(&self.crypto);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service
                .list_keys(tenant, cursor, limit)
                .await
                .map_err(Error::into_pyerr)
        })
    }

    fn __repr__(&self) -> &'static str {
        "_NativeTenant(<redacted>)"
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "native tenant handles cannot be pickled",
        ))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        self.__reduce__()
    }
}

fn copy_buffer(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<PlaintextBuffer> {
    let buffer = PyBuffer::<u8>::get(value)
        .map_err(|_| PyTypeError::new_err("value must support the buffer protocol"))?;
    if !buffer.is_c_contiguous() {
        return Err(Error::Configuration("value buffer must be C-contiguous").into_pyerr());
    }
    if buffer.len_bytes() > MAX_VALUE_SIZE {
        return Err(Error::Configuration("value is too large").into_pyerr());
    }
    let total_len = RECORD_PREFIX_SIZE
        .checked_add(buffer.len_bytes())
        .ok_or_else(|| Error::Configuration("value is too large").into_pyerr())?;
    let mut output =
        PlaintextBuffer::with_record_prefix(vec![0; total_len]).map_err(Error::into_pyerr)?;
    buffer.copy_to_slice(py, output.value_mut().map_err(Error::into_pyerr)?)?;
    Ok(output)
}

fn copy_key_buffer(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let buffer = PyBuffer::<u8>::get(value)
        .map_err(|_| PyTypeError::new_err("value must support the buffer protocol"))?;
    if !buffer.is_c_contiguous() {
        return Err(Error::Configuration("value buffer must be C-contiguous").into_pyerr());
    }
    buffer.to_vec(py)
}

struct SetItemBatch {
    items: Vec<SetItem>,
    value_bytes: usize,
}

impl SetItemBatch {
    fn with_capacity(capacity: usize) -> PyResult<Self> {
        if capacity > MAX_BATCH_ITEMS {
            return Err(Error::Configuration("batch contains more than 10000 items").into_pyerr());
        }
        Ok(Self {
            items: Vec::with_capacity(capacity),
            value_bytes: 0,
        })
    }

    fn push(&mut self, item: SetItem) -> PyResult<()> {
        if self.items.len() >= MAX_BATCH_ITEMS {
            return Err(Error::Configuration("batch contains more than 10000 items").into_pyerr());
        }
        self.value_bytes = self
            .value_bytes
            .checked_add(item.value.len())
            .ok_or_else(|| Error::Configuration("batch values are too large").into_pyerr())?;
        if self.value_bytes > MAX_BATCH_VALUE_BYTES {
            return Err(
                Error::Configuration("batch values exceed the 64 MiB aggregate limit").into_pyerr(),
            );
        }
        self.items.push(item);
        Ok(())
    }

    fn finish(self) -> Vec<SetItem> {
        self.items
    }
}

fn byte_mapping(
    py: Python<'_>,
    values: &Bound<'_, PyAny>,
    expires_at_ms: Option<i64>,
) -> PyResult<Vec<SetItem>> {
    if let Ok(dictionary) = values.cast::<PyDict>() {
        let mut items = SetItemBatch::with_capacity(dictionary.len())?;
        for (key, value) in dictionary.iter() {
            items.push(SetItem {
                key: key.extract()?,
                value: copy_buffer(py, &value)?,
                kind: ValueKind::Bytes,
                expires_at_ms,
            })?;
        }
        return Ok(items.finish());
    }
    let mapping = values
        .cast::<PyMapping>()
        .map_err(|_| PyTypeError::new_err("values must be a mapping"))?;
    let mut items = SetItemBatch::with_capacity(mapping.len()?)?;
    for key in mapping.try_iter()? {
        let key = key?;
        let value = mapping.get_item(&key)?;
        items.push(SetItem {
            key: key.extract()?,
            value: copy_buffer(py, &value)?,
            kind: ValueKind::Bytes,
            expires_at_ms,
        })?;
    }
    Ok(items.finish())
}

fn json_mapping(values: &Bound<'_, PyAny>, expires_at_ms: Option<i64>) -> PyResult<Vec<SetItem>> {
    if let Ok(dictionary) = values.cast::<PyDict>() {
        let mut items = SetItemBatch::with_capacity(dictionary.len())?;
        for (key, value) in dictionary.iter() {
            items.push(SetItem {
                key: key.extract()?,
                value: encode_json(&value)?,
                kind: ValueKind::Json,
                expires_at_ms,
            })?;
        }
        return Ok(items.finish());
    }
    let mapping = values
        .cast::<PyMapping>()
        .map_err(|_| PyTypeError::new_err("values must be a mapping"))?;
    let mut items = SetItemBatch::with_capacity(mapping.len()?)?;
    for key in mapping.try_iter()? {
        let key = key?;
        let value = mapping.get_item(&key)?;
        items.push(SetItem {
            key: key.extract()?,
            value: encode_json(&value)?,
            kind: ValueKind::Json,
            expires_at_ms,
        })?;
    }
    Ok(items.finish())
}

fn string_iterable(values: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if values.is_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(
            "keys must be an iterable of strings, not a string",
        ));
    }
    let mut output = Vec::new();
    for value in values.try_iter()? {
        if output.len() >= MAX_BATCH_ITEMS {
            return Err(Error::Configuration("batch contains more than 10000 items").into_pyerr());
        }
        output.push(value?.extract()?);
    }
    Ok(output)
}

fn byte_result_dict(
    py: Python<'_>,
    keys: Vec<String>,
    entries: Vec<Option<Entry>>,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    for (key, entry) in keys.into_iter().zip(entries) {
        if let Some(entry) = entry {
            result.set_item(key, PyBytes::new(py, entry.value()))?;
        }
    }
    Ok(result.unbind())
}

fn json_result_dict(
    py: Python<'_>,
    keys: Vec<String>,
    values: Vec<Option<JsonDocument>>,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    for (key, value) in keys.into_iter().zip(values) {
        if let Some(value) = value {
            result.set_item(key, value.into_py(py)?)?;
        }
    }
    Ok(result.unbind())
}

fn encode_json(value: &Bound<'_, PyAny>) -> PyResult<PlaintextBuffer> {
    if let Ok(view) = value.extract::<PyRef<'_, JsonObject>>() {
        return view.copy_encoded().map_err(Error::into_pyerr);
    }
    if let Ok(view) = value.extract::<PyRef<'_, JsonArray>>() {
        return view.copy_encoded().map_err(Error::into_pyerr);
    }
    let mut buffer = Vec::with_capacity(RECORD_PREFIX_SIZE + 256);
    buffer.resize(RECORD_PREFIX_SIZE, 0);
    let mut output = PlaintextBuffer::with_record_prefix(buffer).map_err(Error::into_pyerr)?;
    output.buffer_mut().push(JSON_CODEC_VERSION);
    let mut active = ActiveContainers::new();
    encode_json_value(value, 0, &mut active, output.buffer_mut()).map_err(Error::into_pyerr)?;
    if output.len() >= MAX_VALUE_SIZE {
        return Err(Error::Configuration("encoded JSON is too large").into_pyerr());
    }
    Ok(output)
}

fn encode_json_value(
    value: &Bound<'_, PyAny>,
    depth: usize,
    active: &mut ActiveContainers,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if depth > MAX_JSON_DEPTH {
        return Err(Error::Serialization);
    }
    if output.len().saturating_sub(RECORD_PREFIX_SIZE) >= MAX_VALUE_SIZE {
        return Err(Error::Configuration("encoded JSON is too large"));
    }
    if value.is_none() {
        rmp::encode::write_nil(output).map_err(|_| Error::Serialization)?;
    } else if value.is_instance_of::<PyBool>() {
        rmp::encode::write_bool(
            output,
            value.extract::<bool>().map_err(|_| Error::Serialization)?,
        )
        .map_err(|_| Error::Serialization)?;
    } else if value.is_instance_of::<PyInt>() {
        if let Ok(integer) = value.extract::<i64>() {
            rmp::encode::write_sint(output, integer).map_err(|_| Error::Serialization)?;
        } else {
            let integer = value.extract::<u64>().map_err(|_| Error::Serialization)?;
            rmp::encode::write_uint(output, integer).map_err(|_| Error::Serialization)?;
        }
    } else if value.is_instance_of::<PyFloat>() {
        let float = value.extract::<f64>().map_err(|_| Error::Serialization)?;
        if !float.is_finite() {
            return Err(Error::Serialization);
        }
        rmp::encode::write_f64(output, float).map_err(|_| Error::Serialization)?;
    } else if value.is_instance_of::<PyString>() {
        let string = value
            .cast::<PyString>()
            .map_err(|_| Error::Serialization)?
            .to_str()
            .map_err(|_| Error::Serialization)?;
        rmp::encode::write_str(output, string).map_err(|_| Error::Serialization)?;
    } else if value.is_instance_of::<PyList>() {
        let list = value.cast::<PyList>().map_err(|_| Error::Serialization)?;
        let length = u32::try_from(list.len()).map_err(|_| Error::Serialization)?;
        let identity = value.as_ptr() as usize;
        active.enter(identity)?;
        rmp::encode::write_array_len(output, length).map_err(|_| Error::Serialization)?;
        let result = list
            .iter()
            .try_for_each(|item| encode_json_value(&item, depth + 1, active, output));
        active.leave()?;
        result?;
    } else if value.is_instance_of::<PyDict>() {
        let dict = value.cast::<PyDict>().map_err(|_| Error::Serialization)?;
        let length = u32::try_from(dict.len()).map_err(|_| Error::Serialization)?;
        let identity = value.as_ptr() as usize;
        active.enter(identity)?;
        rmp::encode::write_map_len(output, length).map_err(|_| Error::Serialization)?;
        let result = dict.iter().try_for_each(|(key, item)| {
            let key = key.cast::<PyString>().map_err(|_| Error::Serialization)?;
            rmp::encode::write_str(output, key.to_str().map_err(|_| Error::Serialization)?)
                .map_err(|_| Error::Serialization)?;
            encode_json_value(&item, depth + 1, active, output)
        });
        active.leave()?;
        result?;
    } else {
        return Err(Error::Serialization);
    }
    if output.len().saturating_sub(RECORD_PREFIX_SIZE) >= MAX_VALUE_SIZE {
        return Err(Error::Configuration("encoded JSON is too large"));
    }
    Ok(())
}

#[pyfunction]
fn open_store<'py>(
    py: Python<'py>,
    path: String,
    key: PyRef<'_, NativeMasterKey>,
    cleanup_interval_ms: u64,
    engine: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let engine = match engine {
        "redb" => StorageEngine::Redb,
        "sqlite" => StorageEngine::Sqlite,
        _ => return Err(Error::Configuration("unknown storage engine").into_pyerr()),
    };
    let key = key.key.copy();
    let path = PathBuf::from(path);
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let service = Service::open(
            path,
            key,
            Duration::from_millis(cleanup_interval_ms),
            engine,
        )
        .await
        .map_err(Error::into_pyerr)?;
        Ok(NativeStore { service })
    })
}

#[pyfunction]
#[pyo3(signature = (
    endpoint,
    namespace,
    credentials,
    key,
    cleanup_interval_ms,
    timeouts_ms,
))]
fn open_redis_store<'py>(
    py: Python<'py>,
    endpoint: String,
    namespace: String,
    credentials: (Option<String>, Option<String>),
    key: PyRef<'_, NativeMasterKey>,
    cleanup_interval_ms: u64,
    timeouts_ms: (u64, u64, u64),
) -> PyResult<Bound<'py, PyAny>> {
    let (username, password) = credentials;
    let (connect_timeout_ms, response_timeout_ms, durability_timeout_ms) = timeouts_ms;
    let key = key.key.copy();
    let config = RedisConfig {
        endpoint,
        namespace,
        username,
        password,
        connect_timeout: Duration::from_millis(connect_timeout_ms),
        response_timeout: Duration::from_millis(response_timeout_ms),
        durability_timeout: Duration::from_millis(durability_timeout_ms),
    };
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let service = Service::open_redis(config, key, Duration::from_millis(cleanup_interval_ms))
            .await
            .map_err(Error::into_pyerr)?;
        Ok(NativeStore { service })
    })
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("MAX_BATCH_ITEMS", MAX_BATCH_ITEMS)?;
    module.add("MAX_BATCH_VALUE_BYTES", MAX_BATCH_VALUE_BYTES)?;
    module.add("MAX_KEY_LIST_LIMIT", MAX_KEY_LIST_LIMIT)?;
    module.add_class::<NativeMasterKey>()?;
    module.add_class::<NativeStore>()?;
    module.add_class::<NativeTenant>()?;
    module.add_class::<JsonObject>()?;
    module.add_class::<JsonArray>()?;
    module.add_class::<JsonObjectIterator>()?;
    module.add_class::<JsonArrayIterator>()?;
    module.add_function(wrap_pyfunction!(open_store, module)?)?;
    module.add_function(wrap_pyfunction!(open_redis_store, module)?)?;

    let py = module.py();
    module.add("VaultletError", py.get_type::<VaultletError>())?;
    module.add("ConfigurationError", py.get_type::<ConfigurationError>())?;
    module.add("SerializationError", py.get_type::<SerializationError>())?;
    module.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
    module.add("IntegrityError", py.get_type::<IntegrityError>())?;
    module.add(
        "UnsupportedFormatError",
        py.get_type::<UnsupportedFormatError>(),
    )?;
    module.add("StoreLockedError", py.get_type::<StoreLockedError>())?;
    module.add("BackendError", py.get_type::<BackendError>())?;
    module.add("ClosedError", py.get_type::<ClosedError>())?;
    module.add("TypeMismatchError", py.get_type::<TypeMismatchError>())?;
    Ok(())
}
