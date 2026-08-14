use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Arc;

use pyo3::basic::CompareOp;
use pyo3::exceptions::{PyIndexError, PyKeyError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyFloat, PyInt, PyList, PySlice, PyString, PyTuple};
use rmp::Marker;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::format::{JSON_CODEC_VERSION, MAX_VALUE_SIZE, PlaintextBuffer, RECORD_PREFIX_SIZE};
use crate::service::Entry;

const MAX_JSON_DEPTH: usize = 128;
const ARRAY_CHECKPOINT_STRIDE: usize = 32;

#[derive(Clone, Copy)]
enum Container {
    Array {
        content_start: u32,
        end: u32,
        len: u32,
        checkpoints_start: u32,
    },
    Object {
        end: u32,
        entries_start: u32,
        len: u32,
        slots_start: u32,
        slots_len: u32,
    },
}

impl Container {
    fn end(self) -> usize {
        match self {
            Self::Array { end, .. } | Self::Object { end, .. } => end as usize,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ObjectEntry {
    key_start: u32,
    key_len: u32,
    value_offset: u32,
    hash: u64,
}

/// A validated structural index over one zeroizing decrypted MessagePack value.
pub(crate) struct JsonDocument {
    buffer: Zeroizing<Vec<u8>>,
    root_offset: u32,
    containers: HashMap<u32, Container>,
    array_checkpoints: Vec<u32>,
    object_entries: Vec<ObjectEntry>,
    object_slots: Vec<u32>,
    hash_builder: RandomState,
}

impl JsonDocument {
    pub(crate) fn from_entry(entry: Entry) -> Result<Self, Error> {
        let (buffer, value_offset) = entry.into_buffer();
        let value = buffer.get(value_offset..).ok_or(Error::Integrity)?;
        if value.first() != Some(&JSON_CODEC_VERSION) {
            return Err(Error::UnsupportedFormat);
        }
        if value.len() > MAX_VALUE_SIZE {
            return Err(Error::Integrity);
        }
        let root_offset = value_offset.checked_add(1).ok_or(Error::Integrity)?;
        let (containers, array_checkpoints, object_entries, object_slots, hash_builder) = {
            let mut parser = Parser::new(&buffer);
            let end = parser.parse_value(root_offset, 0)?;
            if end != buffer.len() {
                return Err(Error::Integrity);
            }
            (
                parser.containers,
                parser.array_checkpoints,
                parser.object_entries,
                parser.object_slots,
                parser.hash_builder,
            )
        };
        Ok(Self {
            buffer,
            root_offset: u32::try_from(root_offset).map_err(|_| Error::Integrity)?,
            containers,
            array_checkpoints,
            object_entries,
            object_slots,
            hash_builder,
        })
    }

    pub(crate) fn into_py(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let root_offset = self.root_offset;
        value_to_py(py, Arc::new(self), root_offset)
    }

    fn copy_encoded(&self, offset: u32) -> Result<PlaintextBuffer, Error> {
        let end = self.skip_value(offset as usize)?;
        let encoded = self
            .buffer
            .get(offset as usize..end)
            .ok_or(Error::Integrity)?;
        let capacity = RECORD_PREFIX_SIZE
            .checked_add(1)
            .and_then(|value| value.checked_add(encoded.len()))
            .ok_or(Error::Integrity)?;
        let mut buffer = Vec::with_capacity(capacity);
        buffer.resize(RECORD_PREFIX_SIZE, 0);
        let mut output = PlaintextBuffer::with_record_prefix(buffer)?;
        output.buffer_mut().push(JSON_CODEC_VERSION);
        output.buffer_mut().extend_from_slice(encoded);
        Ok(output)
    }

    fn marker(&self, offset: u32) -> Result<Marker, Error> {
        self.buffer
            .get(offset as usize)
            .copied()
            .map(Marker::from_u8)
            .ok_or(Error::Integrity)
    }

    fn container(&self, offset: u32) -> Result<Container, Error> {
        self.containers
            .get(&offset)
            .copied()
            .ok_or(Error::Integrity)
    }

    fn string(&self, offset: u32) -> Result<&str, Error> {
        let (start, len, _) = string_span(&self.buffer, offset as usize)?;
        std::str::from_utf8(
            self.buffer
                .get(start..start.checked_add(len).ok_or(Error::Integrity)?)
                .ok_or(Error::Integrity)?,
        )
        .map_err(|_| Error::Integrity)
    }

    fn array_len(&self, offset: u32) -> Result<usize, Error> {
        match self.container(offset)? {
            Container::Array { len, .. } => Ok(len as usize),
            Container::Object { .. } => Err(Error::Integrity),
        }
    }

    fn array_item(&self, offset: u32, index: usize) -> Result<u32, Error> {
        let Container::Array {
            content_start,
            len,
            checkpoints_start,
            ..
        } = self.container(offset)?
        else {
            return Err(Error::Integrity);
        };
        if index >= len as usize {
            return Err(Error::Integrity);
        }
        let checkpoint_index = index / ARRAY_CHECKPOINT_STRIDE;
        let checkpoint = (checkpoints_start as usize)
            .checked_add(checkpoint_index)
            .ok_or(Error::Integrity)?;
        let mut item_offset = if checkpoint_index == 0 {
            content_start as usize
        } else {
            *self
                .array_checkpoints
                .get(checkpoint)
                .ok_or(Error::Integrity)? as usize
        };
        let checkpoint_item = checkpoint_index * ARRAY_CHECKPOINT_STRIDE;
        for _ in checkpoint_item..index {
            item_offset = self.skip_value(item_offset)?;
        }
        u32::try_from(item_offset).map_err(|_| Error::Integrity)
    }

    fn skip_value(&self, offset: usize) -> Result<usize, Error> {
        let marker = self
            .buffer
            .get(offset)
            .copied()
            .map(Marker::from_u8)
            .ok_or(Error::Integrity)?;
        match marker {
            Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::False | Marker::True => {
                offset.checked_add(1).ok_or(Error::Integrity)
            }
            Marker::U8 | Marker::I8 => checked_end(&self.buffer, offset, 2),
            Marker::U16 | Marker::I16 => checked_end(&self.buffer, offset, 3),
            Marker::U32 | Marker::I32 | Marker::F32 => checked_end(&self.buffer, offset, 5),
            Marker::U64 | Marker::I64 | Marker::F64 => checked_end(&self.buffer, offset, 9),
            Marker::FixStr(_) | Marker::Str8 | Marker::Str16 | Marker::Str32 => {
                string_span(&self.buffer, offset).map(|(_, _, end)| end)
            }
            Marker::FixArray(_)
            | Marker::Array16
            | Marker::Array32
            | Marker::FixMap(_)
            | Marker::Map16
            | Marker::Map32 => self
                .containers
                .get(&u32::try_from(offset).map_err(|_| Error::Integrity)?)
                .copied()
                .map(Container::end)
                .ok_or(Error::Integrity),
            _ => Err(Error::Integrity),
        }
    }

    fn object_metadata(&self, offset: u32) -> Result<(usize, usize, usize, usize), Error> {
        let Container::Object {
            entries_start,
            len,
            slots_start,
            slots_len,
            ..
        } = self.container(offset)?
        else {
            return Err(Error::Integrity);
        };
        Ok((
            entries_start as usize,
            len as usize,
            slots_start as usize,
            slots_len as usize,
        ))
    }

    fn object_entry(&self, offset: u32, index: usize) -> Result<ObjectEntry, Error> {
        let (start, len, _, _) = self.object_metadata(offset)?;
        if index >= len {
            return Err(Error::Integrity);
        }
        self.object_entries
            .get(start.checked_add(index).ok_or(Error::Integrity)?)
            .copied()
            .ok_or(Error::Integrity)
    }

    fn object_lookup(&self, offset: u32, key: &str) -> Result<Option<u32>, Error> {
        let (_, len, slots_start, slots_len) = self.object_metadata(offset)?;
        if len == 0 {
            return Ok(None);
        }
        if slots_len == 0 || !slots_len.is_power_of_two() {
            return Err(Error::Integrity);
        }
        let hash = hash_bytes(&self.hash_builder, key.as_bytes());
        let mut slot = hash as usize & (slots_len - 1);
        for _ in 0..slots_len {
            let stored = *self
                .object_slots
                .get(slots_start.checked_add(slot).ok_or(Error::Integrity)?)
                .ok_or(Error::Integrity)?;
            if stored == 0 {
                return Ok(None);
            }
            let entry = *self
                .object_entries
                .get(stored.checked_sub(1).ok_or(Error::Integrity)? as usize)
                .ok_or(Error::Integrity)?;
            if entry.hash == hash
                && self
                    .buffer
                    .get(
                        entry.key_start as usize
                            ..(entry.key_start as usize)
                                .checked_add(entry.key_len as usize)
                                .ok_or(Error::Integrity)?,
                    )
                    .is_some_and(|stored_key| stored_key == key.as_bytes())
            {
                return Ok(Some(entry.value_offset));
            }
            slot = (slot + 1) & (slots_len - 1);
        }
        Err(Error::Integrity)
    }

    fn materialize_value(self: &Arc<Self>, py: Python<'_>, offset: u32) -> PyResult<Py<PyAny>> {
        match self.marker(offset).map_err(Error::into_pyerr)? {
            Marker::FixArray(_) | Marker::Array16 | Marker::Array32 => {
                let Container::Array {
                    content_start, len, ..
                } = self.container(offset).map_err(Error::into_pyerr)?
                else {
                    return Err(Error::Integrity.into_pyerr());
                };
                let list = PyList::empty(py);
                let mut item = content_start as usize;
                for _ in 0..len {
                    list.append(self.materialize_value(
                        py,
                        u32::try_from(item).map_err(|_| Error::Integrity.into_pyerr())?,
                    )?)?;
                    item = self.skip_value(item).map_err(Error::into_pyerr)?;
                }
                Ok(list.unbind().into_any())
            }
            Marker::FixMap(_) | Marker::Map16 | Marker::Map32 => {
                let (entries_start, len, _, _) =
                    self.object_metadata(offset).map_err(Error::into_pyerr)?;
                let dict = PyDict::new(py);
                for index in 0..len {
                    let entry = *self
                        .object_entries
                        .get(
                            entries_start
                                .checked_add(index)
                                .ok_or(Error::Integrity)
                                .map_err(Error::into_pyerr)?,
                        )
                        .ok_or_else(|| Error::Integrity.into_pyerr())?;
                    let key = std::str::from_utf8(
                        self.buffer
                            .get(
                                entry.key_start as usize
                                    ..(entry.key_start as usize)
                                        .checked_add(entry.key_len as usize)
                                        .ok_or(Error::Integrity)
                                        .map_err(Error::into_pyerr)?,
                            )
                            .ok_or_else(|| Error::Integrity.into_pyerr())?,
                    )
                    .map_err(|_| Error::Integrity.into_pyerr())?;
                    dict.set_item(key, self.materialize_value(py, entry.value_offset)?)?;
                }
                Ok(dict.unbind().into_any())
            }
            _ => scalar_to_py(py, self, offset),
        }
    }
}

struct Parser<'a> {
    input: &'a [u8],
    containers: HashMap<u32, Container>,
    array_checkpoints: Vec<u32>,
    object_entries: Vec<ObjectEntry>,
    object_slots: Vec<u32>,
    hash_builder: RandomState,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            containers: HashMap::new(),
            array_checkpoints: Vec::new(),
            object_entries: Vec::new(),
            object_slots: Vec::new(),
            hash_builder: RandomState::new(),
        }
    }

    fn parse_value(&mut self, offset: usize, depth: usize) -> Result<usize, Error> {
        if depth > MAX_JSON_DEPTH {
            return Err(Error::Serialization);
        }
        let marker = self
            .input
            .get(offset)
            .copied()
            .map(Marker::from_u8)
            .ok_or(Error::Integrity)?;
        match marker {
            Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::False | Marker::True => {
                offset.checked_add(1).ok_or(Error::Integrity)
            }
            Marker::U8 | Marker::I8 => checked_end(self.input, offset, 2),
            Marker::U16 | Marker::I16 => checked_end(self.input, offset, 3),
            Marker::U32 | Marker::I32 => checked_end(self.input, offset, 5),
            Marker::U64 | Marker::I64 => checked_end(self.input, offset, 9),
            Marker::F32 => {
                let end = checked_end(self.input, offset, 5)?;
                let value = f32::from_bits(read_u32(self.input, offset + 1)?);
                if value.is_finite() {
                    Ok(end)
                } else {
                    Err(Error::Integrity)
                }
            }
            Marker::F64 => {
                let end = checked_end(self.input, offset, 9)?;
                let value = f64::from_bits(read_u64(self.input, offset + 1)?);
                if value.is_finite() {
                    Ok(end)
                } else {
                    Err(Error::Integrity)
                }
            }
            Marker::FixStr(_) | Marker::Str8 | Marker::Str16 | Marker::Str32 => {
                let (start, len, end) = string_span(self.input, offset)?;
                std::str::from_utf8(
                    self.input
                        .get(start..start.checked_add(len).ok_or(Error::Integrity)?)
                        .ok_or(Error::Integrity)?,
                )
                .map_err(|_| Error::Integrity)?;
                Ok(end)
            }
            Marker::FixArray(len) => self.parse_array(offset, offset + 1, len.into(), depth),
            Marker::Array16 => {
                let len = read_u16(self.input, offset + 1)? as usize;
                self.parse_array(offset, offset + 3, len, depth)
            }
            Marker::Array32 => {
                let len = usize::try_from(read_u32(self.input, offset + 1)?)
                    .map_err(|_| Error::Integrity)?;
                self.parse_array(offset, offset + 5, len, depth)
            }
            Marker::FixMap(len) => self.parse_object(offset, offset + 1, len.into(), depth),
            Marker::Map16 => {
                let len = read_u16(self.input, offset + 1)? as usize;
                self.parse_object(offset, offset + 3, len, depth)
            }
            Marker::Map32 => {
                let len = usize::try_from(read_u32(self.input, offset + 1)?)
                    .map_err(|_| Error::Integrity)?;
                self.parse_object(offset, offset + 5, len, depth)
            }
            _ => Err(Error::Integrity),
        }
    }

    fn parse_array(
        &mut self,
        marker_offset: usize,
        content_start: usize,
        len: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        if len > self.input.len().saturating_sub(content_start) {
            return Err(Error::Integrity);
        }
        let checkpoint_count = len.div_ceil(ARRAY_CHECKPOINT_STRIDE);
        let checkpoints_start = self.array_checkpoints.len();
        self.array_checkpoints
            .try_reserve(checkpoint_count)
            .map_err(|_| Error::Integrity)?;
        self.array_checkpoints.resize(
            checkpoints_start
                .checked_add(checkpoint_count)
                .ok_or(Error::Integrity)?,
            0,
        );
        let mut cursor = content_start;
        for index in 0..len {
            if index % ARRAY_CHECKPOINT_STRIDE == 0 {
                let checkpoint = checkpoints_start
                    .checked_add(index / ARRAY_CHECKPOINT_STRIDE)
                    .ok_or(Error::Integrity)?;
                self.array_checkpoints[checkpoint] =
                    u32::try_from(cursor).map_err(|_| Error::Integrity)?;
            }
            cursor = self.parse_value(cursor, depth + 1)?;
        }
        self.containers.insert(
            u32::try_from(marker_offset).map_err(|_| Error::Integrity)?,
            Container::Array {
                content_start: u32::try_from(content_start).map_err(|_| Error::Integrity)?,
                end: u32::try_from(cursor).map_err(|_| Error::Integrity)?,
                len: u32::try_from(len).map_err(|_| Error::Integrity)?,
                checkpoints_start: u32::try_from(checkpoints_start)
                    .map_err(|_| Error::Integrity)?,
            },
        );
        Ok(cursor)
    }

    fn parse_object(
        &mut self,
        marker_offset: usize,
        content_start: usize,
        len: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        if len > self.input.len().saturating_sub(content_start) / 2 {
            return Err(Error::Integrity);
        }
        let entries_start = self.object_entries.len();
        self.object_entries
            .try_reserve(len)
            .map_err(|_| Error::Integrity)?;
        self.object_entries.resize(
            entries_start.checked_add(len).ok_or(Error::Integrity)?,
            ObjectEntry::default(),
        );

        let slots_len = if len == 0 {
            0
        } else {
            len.checked_mul(2)
                .and_then(usize::checked_next_power_of_two)
                .ok_or(Error::Integrity)?
        };
        let slots_start = self.object_slots.len();
        self.object_slots
            .try_reserve(slots_len)
            .map_err(|_| Error::Integrity)?;
        self.object_slots.resize(
            slots_start.checked_add(slots_len).ok_or(Error::Integrity)?,
            0,
        );

        let mut cursor = content_start;
        for index in 0..len {
            let (key_start, key_len, key_end) = string_span(self.input, cursor)?;
            let key_bytes = self
                .input
                .get(key_start..key_start.checked_add(key_len).ok_or(Error::Integrity)?)
                .ok_or(Error::Integrity)?;
            std::str::from_utf8(key_bytes).map_err(|_| Error::Integrity)?;
            let hash = hash_bytes(&self.hash_builder, key_bytes);
            cursor = key_end;
            let value_offset = cursor;
            cursor = self.parse_value(cursor, depth + 1)?;
            let entry_index = entries_start.checked_add(index).ok_or(Error::Integrity)?;
            self.object_entries[entry_index] = ObjectEntry {
                key_start: u32::try_from(key_start).map_err(|_| Error::Integrity)?,
                key_len: u32::try_from(key_len).map_err(|_| Error::Integrity)?,
                value_offset: u32::try_from(value_offset).map_err(|_| Error::Integrity)?,
                hash,
            };
            if slots_len != 0 {
                let mut slot = hash as usize & (slots_len - 1);
                loop {
                    let slot_index = slots_start.checked_add(slot).ok_or(Error::Integrity)?;
                    let stored = self.object_slots[slot_index];
                    if stored == 0 {
                        self.object_slots[slot_index] =
                            u32::try_from(entry_index + 1).map_err(|_| Error::Integrity)?;
                        break;
                    }
                    let existing = self
                        .object_entries
                        .get(stored.checked_sub(1).ok_or(Error::Integrity)? as usize)
                        .ok_or(Error::Integrity)?;
                    let existing_key = self
                        .input
                        .get(
                            existing.key_start as usize
                                ..(existing.key_start as usize)
                                    .checked_add(existing.key_len as usize)
                                    .ok_or(Error::Integrity)?,
                        )
                        .ok_or(Error::Integrity)?;
                    if existing.hash == hash && existing_key == key_bytes {
                        return Err(Error::Integrity);
                    }
                    slot = (slot + 1) & (slots_len - 1);
                }
            }
        }
        self.containers.insert(
            u32::try_from(marker_offset).map_err(|_| Error::Integrity)?,
            Container::Object {
                end: u32::try_from(cursor).map_err(|_| Error::Integrity)?,
                entries_start: u32::try_from(entries_start).map_err(|_| Error::Integrity)?,
                len: u32::try_from(len).map_err(|_| Error::Integrity)?,
                slots_start: u32::try_from(slots_start).map_err(|_| Error::Integrity)?,
                slots_len: u32::try_from(slots_len).map_err(|_| Error::Integrity)?,
            },
        );
        Ok(cursor)
    }
}

#[pyclass(name = "_JsonObject", module = "vaultlet._vaultlet", frozen, mapping)]
pub(crate) struct JsonObject {
    document: Arc<JsonDocument>,
    offset: u32,
}

impl JsonObject {
    pub(crate) fn copy_encoded(&self) -> Result<PlaintextBuffer, Error> {
        self.document.copy_encoded(self.offset)
    }
}

#[pymethods]
impl JsonObject {
    fn __len__(&self) -> PyResult<usize> {
        self.document
            .object_metadata(self.offset)
            .map(|(_, len, _, _)| len)
            .map_err(Error::into_pyerr)
    }

    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let key = key
            .cast::<PyString>()
            .map_err(|_| PyKeyError::new_err(key.clone().unbind()))?
            .to_str()?;
        let offset = self
            .document
            .object_lookup(self.offset, key)
            .map_err(Error::into_pyerr)?
            .ok_or_else(|| PyKeyError::new_err(key.to_owned()))?;
        value_to_py(py, Arc::clone(&self.document), offset)
    }

    fn __contains__(&self, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(key) = key.cast::<PyString>() else {
            return Ok(false);
        };
        self.document
            .object_lookup(self.offset, key.to_str()?)
            .map(|value| value.is_some())
            .map_err(Error::into_pyerr)
    }

    #[pyo3(signature = (key, default=None))]
    fn get(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let Some(key) = key.cast::<PyString>().ok() else {
            return Ok(default.unwrap_or_else(|| py.None()));
        };
        match self
            .document
            .object_lookup(self.offset, key.to_str()?)
            .map_err(Error::into_pyerr)?
        {
            Some(offset) => value_to_py(py, Arc::clone(&self.document), offset),
            None => Ok(default.unwrap_or_else(|| py.None())),
        }
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<JsonObjectIterator>> {
        let (_, len, _, _) = self
            .document
            .object_metadata(self.offset)
            .map_err(Error::into_pyerr)?;
        Py::new(
            py,
            JsonObjectIterator {
                document: Arc::clone(&self.document),
                object_offset: self.offset,
                index: 0,
                len,
            },
        )
    }

    fn keys(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let (_, len, _, _) = self
            .document
            .object_metadata(self.offset)
            .map_err(Error::into_pyerr)?;
        let keys = PyList::empty(py);
        for index in 0..len {
            let entry = self
                .document
                .object_entry(self.offset, index)
                .map_err(Error::into_pyerr)?;
            let key = std::str::from_utf8(
                self.document
                    .buffer
                    .get(
                        entry.key_start as usize
                            ..(entry.key_start as usize)
                                .checked_add(entry.key_len as usize)
                                .ok_or(Error::Integrity)
                                .map_err(Error::into_pyerr)?,
                    )
                    .ok_or_else(|| Error::Integrity.into_pyerr())?,
            )
            .map_err(|_| Error::Integrity.into_pyerr())?;
            keys.append(key)?;
        }
        Ok(keys.unbind())
    }

    fn values(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let (_, len, _, _) = self
            .document
            .object_metadata(self.offset)
            .map_err(Error::into_pyerr)?;
        let values = PyList::empty(py);
        for index in 0..len {
            let entry = self
                .document
                .object_entry(self.offset, index)
                .map_err(Error::into_pyerr)?;
            values.append(value_to_py(
                py,
                Arc::clone(&self.document),
                entry.value_offset,
            )?)?;
        }
        Ok(values.unbind())
    }

    fn items(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let (_, len, _, _) = self
            .document
            .object_metadata(self.offset)
            .map_err(Error::into_pyerr)?;
        let items = PyList::empty(py);
        for index in 0..len {
            let entry = self
                .document
                .object_entry(self.offset, index)
                .map_err(Error::into_pyerr)?;
            let key = std::str::from_utf8(
                self.document
                    .buffer
                    .get(
                        entry.key_start as usize
                            ..(entry.key_start as usize)
                                .checked_add(entry.key_len as usize)
                                .ok_or(Error::Integrity)
                                .map_err(Error::into_pyerr)?,
                    )
                    .ok_or_else(|| Error::Integrity.into_pyerr())?,
            )
            .map_err(|_| Error::Integrity.into_pyerr())?;
            let value = value_to_py(py, Arc::clone(&self.document), entry.value_offset)?;
            items.append(PyTuple::new(
                py,
                [key.into_pyobject(py)?.into_any(), value.bind(py).clone()],
            )?)?;
        }
        Ok(items.unbind())
    }

    fn to_builtin(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.document.materialize_value(py, self.offset)
    }

    fn __richcmp__(
        &self,
        py: Python<'_>,
        other: &Bound<'_, PyAny>,
        operation: CompareOp,
    ) -> PyResult<Py<PyAny>> {
        rich_compare_materialized(
            py,
            self.document.materialize_value(py, self.offset)?,
            other,
            operation,
        )
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("JsonObject(len={})", self.__len__()?))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "immutable JSON views cannot be pickled",
        ))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        self.__reduce__()
    }
}

#[pyclass(name = "_JsonArray", module = "vaultlet._vaultlet", frozen, sequence)]
pub(crate) struct JsonArray {
    document: Arc<JsonDocument>,
    offset: u32,
}

impl JsonArray {
    pub(crate) fn copy_encoded(&self) -> Result<PlaintextBuffer, Error> {
        self.document.copy_encoded(self.offset)
    }
}

#[pymethods]
impl JsonArray {
    fn __len__(&self) -> PyResult<usize> {
        self.document
            .array_len(self.offset)
            .map_err(Error::into_pyerr)
    }

    fn __getitem__(&self, py: Python<'_>, index: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let len = self.__len__()?;
        if let Ok(slice) = index.cast::<PySlice>() {
            let indices =
                slice.indices(isize::try_from(len).map_err(|_| Error::Integrity.into_pyerr())?)?;
            let tuple = PyTuple::empty(py);
            if indices.slicelength == 0 {
                return Ok(tuple.unbind().into_any());
            }
            let mut values = Vec::with_capacity(indices.slicelength);
            let mut current = indices.start;
            for _ in 0..indices.slicelength {
                let item = self
                    .document
                    .array_item(self.offset, current as usize)
                    .map_err(Error::into_pyerr)?;
                values.push(value_to_py(py, Arc::clone(&self.document), item)?);
                current += indices.step;
            }
            return Ok(PyTuple::new(py, values)?.unbind().into_any());
        }
        let mut index = index
            .extract::<isize>()
            .map_err(|_| PyTypeError::new_err("JSON array indices must be integers or slices"))?;
        let signed_len = isize::try_from(len).map_err(|_| Error::Integrity.into_pyerr())?;
        if index < 0 {
            index += signed_len;
        }
        if index < 0 || index >= signed_len {
            return Err(PyIndexError::new_err("JSON array index out of range"));
        }
        let item = self
            .document
            .array_item(self.offset, index as usize)
            .map_err(Error::into_pyerr)?;
        value_to_py(py, Arc::clone(&self.document), item)
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<JsonArrayIterator>> {
        let len = self.__len__()?;
        let first = if len == 0 {
            None
        } else {
            Some(
                self.document
                    .array_item(self.offset, 0)
                    .map_err(Error::into_pyerr)?,
            )
        };
        Py::new(
            py,
            JsonArrayIterator {
                document: Arc::clone(&self.document),
                next_offset: first,
                remaining: len,
            },
        )
    }

    fn count(&self, py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<usize> {
        let mut count = 0;
        for index in 0..self.__len__()? {
            let offset = self
                .document
                .array_item(self.offset, index)
                .map_err(Error::into_pyerr)?;
            if value_to_py(py, Arc::clone(&self.document), offset)?
                .bind(py)
                .eq(value)?
            {
                count += 1;
            }
        }
        Ok(count)
    }

    #[pyo3(signature = (value, start=0, stop=None))]
    fn index(
        &self,
        py: Python<'_>,
        value: &Bound<'_, PyAny>,
        start: isize,
        stop: Option<isize>,
    ) -> PyResult<usize> {
        let len = self.__len__()?;
        let signed_len = isize::try_from(len).map_err(|_| Error::Integrity.into_pyerr())?;
        let normalize = |index: isize| {
            if index < 0 {
                (index + signed_len).max(0)
            } else {
                index.min(signed_len)
            }
        };
        let start = normalize(start) as usize;
        let stop = normalize(stop.unwrap_or(signed_len)) as usize;
        for index in start..stop {
            let offset = self
                .document
                .array_item(self.offset, index)
                .map_err(Error::into_pyerr)?;
            if value_to_py(py, Arc::clone(&self.document), offset)?
                .bind(py)
                .eq(value)?
            {
                return Ok(index);
            }
        }
        Err(pyo3::exceptions::PyValueError::new_err(
            "value is not in JSON array",
        ))
    }

    fn to_builtin(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.document.materialize_value(py, self.offset)
    }

    fn __richcmp__(
        &self,
        py: Python<'_>,
        other: &Bound<'_, PyAny>,
        operation: CompareOp,
    ) -> PyResult<Py<PyAny>> {
        rich_compare_materialized(
            py,
            self.document.materialize_value(py, self.offset)?,
            other,
            operation,
        )
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("JsonArray(len={})", self.__len__()?))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "immutable JSON views cannot be pickled",
        ))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        self.__reduce__()
    }
}

#[pyclass(module = "vaultlet._vaultlet")]
pub(crate) struct JsonObjectIterator {
    document: Arc<JsonDocument>,
    object_offset: u32,
    index: usize,
    len: usize,
}

#[pymethods]
impl JsonObjectIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyString>>> {
        if self.index >= self.len {
            return Ok(None);
        }
        let entry = self
            .document
            .object_entry(self.object_offset, self.index)
            .map_err(Error::into_pyerr)?;
        self.index += 1;
        let key = self
            .document
            .buffer
            .get(
                entry.key_start as usize
                    ..(entry.key_start as usize)
                        .checked_add(entry.key_len as usize)
                        .ok_or(Error::Integrity)
                        .map_err(Error::into_pyerr)?,
            )
            .ok_or_else(|| Error::Integrity.into_pyerr())?;
        let key = std::str::from_utf8(key).map_err(|_| Error::Integrity.into_pyerr())?;
        Ok(Some(PyString::new(py, key).unbind()))
    }
}

#[pyclass(module = "vaultlet._vaultlet")]
pub(crate) struct JsonArrayIterator {
    document: Arc<JsonDocument>,
    next_offset: Option<u32>,
    remaining: usize,
}

#[pymethods]
impl JsonArrayIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let offset = self
            .next_offset
            .ok_or_else(|| Error::Integrity.into_pyerr())?;
        self.remaining -= 1;
        self.next_offset = if self.remaining == 0 {
            None
        } else {
            Some(
                u32::try_from(
                    self.document
                        .skip_value(offset as usize)
                        .map_err(Error::into_pyerr)?,
                )
                .map_err(|_| Error::Integrity.into_pyerr())?,
            )
        };
        value_to_py(py, Arc::clone(&self.document), offset).map(Some)
    }
}

fn value_to_py(py: Python<'_>, document: Arc<JsonDocument>, offset: u32) -> PyResult<Py<PyAny>> {
    match document.marker(offset).map_err(Error::into_pyerr)? {
        Marker::FixArray(_) | Marker::Array16 | Marker::Array32 => {
            Py::new(py, JsonArray { document, offset }).map(Py::into_any)
        }
        Marker::FixMap(_) | Marker::Map16 | Marker::Map32 => {
            Py::new(py, JsonObject { document, offset }).map(Py::into_any)
        }
        _ => scalar_to_py(py, &document, offset),
    }
}

fn scalar_to_py(py: Python<'_>, document: &JsonDocument, offset: u32) -> PyResult<Py<PyAny>> {
    let offset = offset as usize;
    let marker = document.marker(offset as u32).map_err(Error::into_pyerr)?;
    match marker {
        Marker::Null => Ok(py.None()),
        Marker::False => Ok(PyBool::new(py, false).to_owned().unbind().into_any()),
        Marker::True => Ok(PyBool::new(py, true).to_owned().unbind().into_any()),
        Marker::FixPos(value) => Ok(PyInt::new(py, value).unbind().into_any()),
        Marker::FixNeg(value) => Ok(PyInt::new(py, value).unbind().into_any()),
        Marker::U8 => Ok(PyInt::new(
            py,
            read_u8(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::U16 => Ok(PyInt::new(
            py,
            read_u16(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::U32 => Ok(PyInt::new(
            py,
            read_u32(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::U64 => Ok(PyInt::new(
            py,
            read_u64(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::I8 => Ok(PyInt::new(
            py,
            read_i8(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::I16 => Ok(PyInt::new(
            py,
            read_i16(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::I32 => Ok(PyInt::new(
            py,
            read_i32(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::I64 => Ok(PyInt::new(
            py,
            read_i64(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        Marker::F32 => Ok(PyFloat::new(
            py,
            f64::from(f32::from_bits(
                read_u32(&document.buffer, offset + 1).map_err(Error::into_pyerr)?,
            )),
        )
        .unbind()
        .into_any()),
        Marker::F64 => Ok(PyFloat::new(
            py,
            f64::from_bits(read_u64(&document.buffer, offset + 1).map_err(Error::into_pyerr)?),
        )
        .unbind()
        .into_any()),
        Marker::FixStr(_) | Marker::Str8 | Marker::Str16 | Marker::Str32 => Ok(PyString::new(
            py,
            document.string(offset as u32).map_err(Error::into_pyerr)?,
        )
        .unbind()
        .into_any()),
        _ => Err(Error::Integrity.into_pyerr()),
    }
}

fn rich_compare_materialized(
    py: Python<'_>,
    materialized: Py<PyAny>,
    other: &Bound<'_, PyAny>,
    operation: CompareOp,
) -> PyResult<Py<PyAny>> {
    match operation {
        CompareOp::Eq | CompareOp::Ne => materialized
            .bind(py)
            .rich_compare(other, operation)
            .map(Bound::unbind),
        _ => Ok(py.NotImplemented()),
    }
}

fn hash_bytes(hash_builder: &RandomState, value: &[u8]) -> u64 {
    hash_builder.hash_one(value)
}

fn checked_end(input: &[u8], offset: usize, len: usize) -> Result<usize, Error> {
    let end = offset.checked_add(len).ok_or(Error::Integrity)?;
    input.get(offset..end).ok_or(Error::Integrity)?;
    Ok(end)
}

fn string_span(input: &[u8], offset: usize) -> Result<(usize, usize, usize), Error> {
    let marker = input
        .get(offset)
        .copied()
        .map(Marker::from_u8)
        .ok_or(Error::Integrity)?;
    let (header_len, len) = match marker {
        Marker::FixStr(len) => (1, len as usize),
        Marker::Str8 => (2, read_u8(input, offset + 1)? as usize),
        Marker::Str16 => (3, read_u16(input, offset + 1)? as usize),
        Marker::Str32 => (
            5,
            usize::try_from(read_u32(input, offset + 1)?).map_err(|_| Error::Integrity)?,
        ),
        _ => return Err(Error::Integrity),
    };
    let start = offset.checked_add(header_len).ok_or(Error::Integrity)?;
    let end = start.checked_add(len).ok_or(Error::Integrity)?;
    input.get(start..end).ok_or(Error::Integrity)?;
    Ok((start, len, end))
}

fn read_u8(input: &[u8], offset: usize) -> Result<u8, Error> {
    input.get(offset).copied().ok_or(Error::Integrity)
}

fn read_i8(input: &[u8], offset: usize) -> Result<i8, Error> {
    read_u8(input, offset).map(|value| value as i8)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        input
            .get(offset..offset.checked_add(2).ok_or(Error::Integrity)?)
            .ok_or(Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?,
    ))
}

fn read_i16(input: &[u8], offset: usize) -> Result<i16, Error> {
    read_u16(input, offset).map(|value| value as i16)
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        input
            .get(offset..offset.checked_add(4).ok_or(Error::Integrity)?)
            .ok_or(Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?,
    ))
}

fn read_i32(input: &[u8], offset: usize) -> Result<i32, Error> {
    read_u32(input, offset).map(|value| value as i32)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        input
            .get(offset..offset.checked_add(8).ok_or(Error::Integrity)?)
            .ok_or(Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?,
    ))
}

fn read_i64(input: &[u8], offset: usize) -> Result<i64, Error> {
    read_u64(input, offset).map(|value| value as i64)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::JsonDocument;
    use crate::format::JSON_CODEC_VERSION;
    use crate::service::Entry;

    fn document(encoded: Vec<u8>) -> JsonDocument {
        let mut value = vec![0; 7];
        value.push(JSON_CODEC_VERSION);
        value.extend(encoded);
        JsonDocument::from_entry(Entry::from_buffer(Zeroizing::new(value), 7))
            .expect("valid JSON document")
    }

    #[test]
    fn indexes_nested_arrays_and_objects() {
        let mut encoded = Vec::new();
        rmp::encode::write_map_len(&mut encoded, 2).expect("map");
        rmp::encode::write_str(&mut encoded, "array").expect("key");
        rmp::encode::write_array_len(&mut encoded, 70).expect("array");
        for value in 0..70_u64 {
            rmp::encode::write_uint(&mut encoded, value).expect("value");
        }
        rmp::encode::write_str(&mut encoded, "nested").expect("key");
        rmp::encode::write_map_len(&mut encoded, 1).expect("map");
        rmp::encode::write_str(&mut encoded, "ok").expect("key");
        rmp::encode::write_bool(&mut encoded, true).expect("value");

        let document = document(encoded);
        let array = document
            .object_lookup(document.root_offset, "array")
            .expect("lookup")
            .expect("array");
        assert_eq!(document.array_len(array).expect("length"), 70);
        let last = document.array_item(array, 69).expect("last item");
        assert!(matches!(document.marker(last), Ok(rmp::Marker::FixPos(69))));
        assert!(
            document
                .object_lookup(document.root_offset, "missing")
                .expect("lookup")
                .is_none()
        );
    }

    #[test]
    fn rejects_trailing_invalid_and_duplicate_values() {
        assert!(
            JsonDocument::from_entry(Entry::from_buffer(
                Zeroizing::new(vec![JSON_CODEC_VERSION, 0xc0, 0xc0]),
                0,
            ))
            .is_err()
        );
        assert!(
            JsonDocument::from_entry(Entry::from_buffer(
                Zeroizing::new(vec![JSON_CODEC_VERSION, 0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0]),
                0,
            ))
            .is_err()
        );

        let mut duplicate = vec![JSON_CODEC_VERSION];
        rmp::encode::write_map_len(&mut duplicate, 2).expect("map");
        for value in [1, 2] {
            rmp::encode::write_str(&mut duplicate, "same").expect("key");
            rmp::encode::write_sint(&mut duplicate, value).expect("value");
        }
        assert!(
            JsonDocument::from_entry(Entry::from_buffer(Zeroizing::new(duplicate), 0,)).is_err()
        );
    }
}
