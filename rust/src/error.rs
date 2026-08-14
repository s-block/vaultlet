use pyo3::PyErr;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use std::error::Error as StdError;
use thiserror::Error;

create_exception!(_vaultlet, VaultletError, PyException);
create_exception!(_vaultlet, ConfigurationError, VaultletError);
create_exception!(_vaultlet, SerializationError, VaultletError);
create_exception!(_vaultlet, InvalidKeyError, VaultletError);
create_exception!(_vaultlet, IntegrityError, VaultletError);
create_exception!(_vaultlet, UnsupportedFormatError, IntegrityError);
create_exception!(_vaultlet, StoreLockedError, VaultletError);
create_exception!(_vaultlet, BackendError, VaultletError);
create_exception!(_vaultlet, ClosedError, VaultletError);
create_exception!(_vaultlet, TypeMismatchError, VaultletError);

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("invalid Vaultlet configuration: {0}")]
    Configuration(&'static str),
    #[error("value cannot be represented by Vaultlet JSON")]
    Serialization,
    #[error("the master key does not match this store")]
    InvalidKey,
    #[error("stored data failed integrity validation")]
    Integrity,
    #[error("the store uses an unsupported format version")]
    UnsupportedFormat,
    #[error("the store is already open by another owner")]
    StoreLocked,
    #[error("the storage backend failed: {source}")]
    Backend {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("the storage backend failed: {0}")]
    BackendState(&'static str),
    #[error("the Vaultlet store is closed")]
    Closed,
    #[error("the stored value has a different kind")]
    TypeMismatch,
    #[error("a blocking storage task failed")]
    BlockingTask,
}

impl Error {
    pub(crate) fn into_pyerr(self) -> PyErr {
        let message = self.to_string();
        match self {
            Self::Configuration(_) => ConfigurationError::new_err(message),
            Self::Serialization => SerializationError::new_err(message),
            Self::InvalidKey => InvalidKeyError::new_err(message),
            Self::Integrity => IntegrityError::new_err(message),
            Self::UnsupportedFormat => UnsupportedFormatError::new_err(message),
            Self::StoreLocked => StoreLockedError::new_err(message),
            Self::Closed => ClosedError::new_err(message),
            Self::TypeMismatch => TypeMismatchError::new_err(message),
            Self::Backend { .. } | Self::BackendState(_) | Self::BlockingTask => {
                BackendError::new_err(message)
            }
        }
    }

    pub(crate) fn backend(error: impl StdError + Send + Sync + 'static) -> Self {
        let message = error.to_string();
        let normalized = message.to_ascii_lowercase();
        if normalized.contains("corrupt") {
            Self::Integrity
        } else if normalized.contains("upgrade required") || normalized.contains("format version") {
            Self::UnsupportedFormat
        } else if normalized.contains("already open") {
            Self::StoreLocked
        } else {
            Self::Backend {
                source: Box::new(error),
            }
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(error: tokio::task::JoinError) -> Self {
        if error.is_panic() {
            Self::Integrity
        } else {
            Self::BlockingTask
        }
    }
}
