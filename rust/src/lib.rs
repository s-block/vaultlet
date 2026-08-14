#![forbid(unsafe_code)]

mod backend;
#[doc(hidden)]
pub mod benchmark_support;
mod bindings;
mod crypto;
mod error;
mod format;
mod json;
mod service;

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[pymodule]
fn _vaultlet(module: &Bound<'_, PyModule>) -> PyResult<()> {
    bindings::register(module)
}
