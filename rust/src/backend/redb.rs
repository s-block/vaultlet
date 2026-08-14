use std::fs::{self, OpenOptions};
use std::ops::Bound::{Excluded, Included};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use redb::{Database, DatabaseError, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use super::{
    Backend, CatalogEntry, CatalogPage, CleanupCandidate, ExpiryCandidate, ExpiryRecord, Mutation,
    RecordId, TenantToken, decode_put_envelopes,
};
use crate::error::Error;
use crate::format::{EnvelopeMetadata, EnvelopeRef, decode_expiry_index_key, expiry_index_key};

const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("vaultlet.metadata.v1");
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vaultlet.records.v1");
const CATALOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vaultlet.catalog.v1");
const EXPIRY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vaultlet.expiry.v1");
const HEADER_KEY: &str = "header";
const EXPIRY_BATCH_LIMIT: usize = 10_000;
const BLOCKING_OPERATION_LIMIT: usize = 32;

pub(crate) struct RedbBackend {
    database: Mutex<Option<Arc<Database>>>,
    writer_gate: Arc<AsyncMutex<()>>,
    blocking_gate: Arc<Semaphore>,
}

impl RedbBackend {
    pub(crate) async fn open(path: PathBuf) -> Result<Arc<Self>, Error> {
        tokio::task::spawn_blocking(move || Self::open_blocking(&path)).await?
    }

    fn open_blocking(path: &Path) -> Result<Arc<Self>, Error> {
        let existing = fs::symlink_metadata(path);
        let is_new = match existing {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Configuration("store paths cannot be symbolic links"));
                }
                if !metadata.is_file() {
                    return Err(Error::Configuration("store path must be a regular file"));
                }
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(Error::backend(error)),
        };

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        configure_open_options(&mut options, is_new);
        if is_new {
            options.create_new(true);
        }
        let file = options.open(path).map_err(Error::backend)?;
        if !file.metadata().map_err(Error::backend)?.is_file() {
            return Err(Error::Configuration("store path must be a regular file"));
        }
        let database = Database::builder()
            .create_file(file)
            .map_err(map_database_error)?;
        Ok(Arc::new(Self {
            database: Mutex::new(Some(Arc::new(database))),
            writer_gate: Arc::new(AsyncMutex::new(())),
            blocking_gate: Arc::new(Semaphore::new(BLOCKING_OPERATION_LIMIT)),
        }))
    }

    fn database(&self) -> Result<Arc<Database>, Error> {
        self.database
            .lock()
            .map_err(|_| Error::BackendState("backend state is unavailable"))?
            .clone()
            .ok_or(Error::Closed)
    }

    async fn writer_context(&self) -> Result<(Arc<Database>, OwnedMutexGuard<()>), Error> {
        let database = self.database()?;
        let gate = Arc::clone(&self.writer_gate).lock_owned().await;
        Ok((database, gate))
    }

    async fn read_context(&self) -> Result<(Arc<Database>, OwnedSemaphorePermit), Error> {
        let database = self.database()?;
        let permit = Arc::clone(&self.blocking_gate)
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)?;
        Ok((database, permit))
    }
}

#[async_trait]
impl Backend for RedbBackend {
    async fn load_or_initialize_header(&self, candidate: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (database, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let mut transaction = database.begin_write().map_err(Error::backend)?;
            configure_transaction(&mut transaction)?;
            let stored = {
                let metadata = transaction.open_table(METADATA).map_err(Error::backend)?;
                let current = metadata
                    .get(HEADER_KEY)
                    .map_err(Error::backend)?
                    .map(|value| value.value().to_vec());
                if let Some(current) = current {
                    current
                } else {
                    let metadata_empty = metadata
                        .iter()
                        .map_err(Error::backend)?
                        .next()
                        .transpose()
                        .map_err(Error::backend)?
                        .is_none();
                    drop(metadata);
                    let records_empty = table_is_empty(&transaction, RECORDS)?;
                    let catalog_empty = table_is_empty(&transaction, CATALOG)?;
                    let expiry_empty = table_is_empty(&transaction, EXPIRY)?;
                    if !metadata_empty || !records_empty || !catalog_empty || !expiry_empty {
                        return Err(Error::Integrity);
                    }
                    let mut metadata = transaction.open_table(METADATA).map_err(Error::backend)?;
                    metadata
                        .insert(HEADER_KEY, candidate.as_slice())
                        .map_err(Error::backend)?;
                    candidate
                }
            };
            transaction.commit().map_err(Error::backend)?;
            Ok(stored)
        })
        .await?
    }

    async fn replace_header(&self, expected: Vec<u8>, replacement: Vec<u8>) -> Result<bool, Error> {
        let (database, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let mut transaction = database.begin_write().map_err(Error::backend)?;
            configure_transaction(&mut transaction)?;
            let changed = {
                let mut metadata = transaction.open_table(METADATA).map_err(Error::backend)?;
                let current = metadata
                    .get(HEADER_KEY)
                    .map_err(Error::backend)?
                    .map(|value| value.value().to_vec());
                if current.as_ref() == Some(&expected) {
                    metadata
                        .insert(HEADER_KEY, replacement.as_slice())
                        .map_err(Error::backend)?;
                    true
                } else {
                    false
                }
            };
            transaction.commit().map_err(Error::backend)?;
            Ok(changed)
        })
        .await?
    }

    async fn read_many(&self, record_ids: Vec<RecordId>) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let (database, permit) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let transaction = database.begin_read().map_err(Error::backend)?;
            let records = transaction
                .open_table(RECORDS)
                .map_err(|_| Error::Integrity)?;
            record_ids
                .iter()
                .map(|record_id| {
                    records
                        .get(record_id.as_slice())
                        .map_err(Error::backend)
                        .map(|value| value.map(|guard| guard.value().to_vec()))
                })
                .collect()
        })
        .await?
    }

    async fn read_one(&self, record_id: RecordId) -> Result<Option<Vec<u8>>, Error> {
        let (database, permit) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let transaction = database.begin_read().map_err(Error::backend)?;
            let records = transaction
                .open_table(RECORDS)
                .map_err(|_| Error::Integrity)?;
            records
                .get(record_id.as_slice())
                .map_err(Error::backend)
                .map(|value| value.map(|guard| guard.value().to_vec()))
        })
        .await?
    }

    async fn list_catalog(
        &self,
        tenant_token: TenantToken,
        after: Option<RecordId>,
        limit: usize,
    ) -> Result<CatalogPage, Error> {
        let (database, permit) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let transaction = database.begin_read().map_err(Error::backend)?;
            let catalog = transaction
                .open_table(CATALOG)
                .map_err(|_| Error::Integrity)?;
            let records = transaction
                .open_table(RECORDS)
                .map_err(|_| Error::Integrity)?;
            let start = catalog_key(&tenant_token, &after.unwrap_or([0; 32]));
            let end = catalog_key(&tenant_token, &[u8::MAX; 32]);
            let start_bound = if after.is_some() {
                Excluded(start.as_slice())
            } else {
                Included(start.as_slice())
            };
            let entries = catalog
                .range::<&[u8]>((start_bound, Included(end.as_slice())))
                .map_err(Error::backend)?
                .take(CatalogPage::fetch_limit(limit)?)
                .map(|row| {
                    let (raw_key, key_envelope) = row.map_err(Error::backend)?;
                    let raw_key = raw_key.value();
                    let record_id: RecordId = raw_key
                        .get(32..)
                        .ok_or(Error::Integrity)?
                        .try_into()
                        .map_err(|_| Error::Integrity)?;
                    records
                        .get(record_id.as_slice())
                        .map_err(Error::backend)?
                        .ok_or(Error::Integrity)?;
                    Ok(CatalogEntry {
                        record_id,
                        key_envelope: key_envelope.value().to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            CatalogPage::from_lookahead(entries, limit)
        })
        .await?
    }

    async fn mutate(&self, mutations: Vec<Mutation>) -> Result<Vec<bool>, Error> {
        let (database, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let mutation_count = mutations.len();
            let mut transaction = database.begin_write().map_err(Error::backend)?;
            configure_transaction(&mut transaction)?;
            let mut results = Vec::with_capacity(mutations.len());
            {
                let mut records = transaction.open_table(RECORDS).map_err(Error::backend)?;
                let mut catalog = transaction.open_table(CATALOG).map_err(Error::backend)?;
                let mut expiry = transaction.open_table(EXPIRY).map_err(Error::backend)?;
                for mutation in mutations {
                    match mutation {
                        Mutation::Put {
                            record_id,
                            envelope,
                            tenant_token,
                            key_envelope,
                        } => {
                            let previous = records
                                .get(record_id.as_slice())
                                .map_err(Error::backend)?
                                .map(|guard| {
                                    EnvelopeRef::parse(guard.value()).map(|value| value.metadata())
                                })
                                .transpose()?;
                            if let Some(previous) = previous {
                                remove_indexes_for_metadata(
                                    &mut catalog,
                                    &mut expiry,
                                    &record_id,
                                    &previous,
                                )?;
                            }
                            let decoded =
                                decode_put_envelopes(&envelope, &key_envelope, &tenant_token)?;
                            records
                                .insert(record_id.as_slice(), envelope.as_slice())
                                .map_err(Error::backend)?;
                            let catalog_index = catalog_key(&tenant_token, &record_id);
                            catalog
                                .insert(catalog_index.as_slice(), key_envelope.as_slice())
                                .map_err(Error::backend)?;
                            if let Some(expires_at_ms) = decoded.expires_at_ms {
                                let index =
                                    expiry_index_key(expires_at_ms, &record_id, &decoded.revision);
                                let empty: &[u8] = &[];
                                expiry
                                    .insert(index.as_slice(), empty)
                                    .map_err(Error::backend)?;
                            }
                            results.push(true);
                        }
                        Mutation::DeleteGuarded {
                            record_id,
                            revision,
                        } => {
                            let current = records
                                .get(record_id.as_slice())
                                .map_err(Error::backend)?
                                .map(|guard| {
                                    EnvelopeRef::parse(guard.value()).map(|value| value.metadata())
                                })
                                .transpose()?;
                            if let Some(current) = current {
                                if current.revision != revision {
                                    return Ok(vec![false; mutation_count]);
                                }
                                remove_indexes_for_metadata(
                                    &mut catalog,
                                    &mut expiry,
                                    &record_id,
                                    &current,
                                )?;
                                records
                                    .remove(record_id.as_slice())
                                    .map_err(Error::backend)?;
                                results.push(true);
                            } else {
                                return Ok(vec![false; mutation_count]);
                            }
                        }
                        Mutation::DeleteAny { record_id } => {
                            let current = records
                                .get(record_id.as_slice())
                                .map_err(Error::backend)?
                                .map(|guard| {
                                    EnvelopeRef::parse(guard.value()).map(|value| value.metadata())
                                })
                                .transpose()?;
                            if let Some(ref current) = current {
                                remove_indexes_for_metadata(
                                    &mut catalog,
                                    &mut expiry,
                                    &record_id,
                                    current,
                                )?;
                                records
                                    .remove(record_id.as_slice())
                                    .map_err(Error::backend)?;
                            }
                            results.push(current.is_some());
                        }
                    }
                }
            }
            transaction.commit().map_err(Error::backend)?;
            Ok(results)
        })
        .await?
    }

    async fn scan_due(&self, now_ms: i64, limit: usize) -> Result<Vec<ExpiryCandidate>, Error> {
        let (database, permit) = self.read_context().await?;
        let limit = limit.min(EXPIRY_BATCH_LIMIT);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let transaction = database.begin_read().map_err(Error::backend)?;
            let expiry = transaction
                .open_table(EXPIRY)
                .map_err(|_| Error::Integrity)?;
            let mut candidates = Vec::with_capacity(limit);
            for entry in expiry.iter().map_err(Error::backend)? {
                let (key, _) = entry.map_err(Error::backend)?;
                let bytes = key.value();
                let (expires_at_ms, record_id, revision) = decode_expiry_index_key(bytes)?;
                if expires_at_ms > now_ms || candidates.len() == limit {
                    break;
                }
                candidates.push(ExpiryCandidate {
                    index_key: bytes.try_into().map_err(|_| Error::Integrity)?,
                    expires_at_ms,
                    record_id,
                    revision,
                });
            }
            Ok(candidates)
        })
        .await?
    }

    async fn scan_due_records(
        &self,
        now_ms: i64,
        record_limit: usize,
        byte_limit: usize,
    ) -> Result<Vec<ExpiryRecord>, Error> {
        let (database, permit) = self.read_context().await?;
        let record_limit = record_limit.min(EXPIRY_BATCH_LIMIT);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let transaction = database.begin_read().map_err(Error::backend)?;
            let expiry = transaction
                .open_table(EXPIRY)
                .map_err(|_| Error::Integrity)?;
            let records_table = transaction
                .open_table(RECORDS)
                .map_err(|_| Error::Integrity)?;
            let mut records = Vec::with_capacity(record_limit);
            let mut total_bytes = 0_usize;
            for entry in expiry.iter().map_err(Error::backend)? {
                let (key, _) = entry.map_err(Error::backend)?;
                let bytes = key.value();
                let (expires_at_ms, record_id, revision) = decode_expiry_index_key(bytes)?;
                if expires_at_ms > now_ms || records.len() == record_limit {
                    break;
                }
                let envelope = records_table
                    .get(record_id.as_slice())
                    .map_err(Error::backend)?
                    .map(|guard| guard.value().to_vec());
                let next_bytes = envelope.as_ref().map_or(0, Vec::len);
                if !records.is_empty() && total_bytes.saturating_add(next_bytes) > byte_limit {
                    break;
                }
                total_bytes = total_bytes.saturating_add(next_bytes);
                records.push(ExpiryRecord {
                    candidate: ExpiryCandidate {
                        index_key: bytes.try_into().map_err(|_| Error::Integrity)?,
                        expires_at_ms,
                        record_id,
                        revision,
                    },
                    envelope,
                });
            }
            Ok(records)
        })
        .await?
    }

    async fn cleanup_candidates(&self, candidates: Vec<CleanupCandidate>) -> Result<usize, Error> {
        let (database, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let mut transaction = database.begin_write().map_err(Error::backend)?;
            configure_transaction(&mut transaction)?;
            let deleted = {
                let mut records = transaction.open_table(RECORDS).map_err(Error::backend)?;
                let mut catalog = transaction.open_table(CATALOG).map_err(Error::backend)?;
                let mut expiry = transaction.open_table(EXPIRY).map_err(Error::backend)?;
                let mut deleted = 0;
                for cleanup in candidates {
                    let candidate = cleanup.candidate;
                    let current = records
                        .get(candidate.record_id.as_slice())
                        .map_err(Error::backend)?
                        .map(|guard| {
                            EnvelopeRef::parse(guard.value()).map(|value| value.metadata())
                        })
                        .transpose()?;
                    let should_delete = current
                        .as_ref()
                        .is_some_and(|value| value.revision == candidate.revision)
                        && cleanup.delete_current;
                    if should_delete {
                        remove_indexes_for_metadata(
                            &mut catalog,
                            &mut expiry,
                            &candidate.record_id,
                            current.as_ref().ok_or(Error::Integrity)?,
                        )?;
                        records
                            .remove(candidate.record_id.as_slice())
                            .map_err(Error::backend)?;
                        deleted += 1;
                    } else {
                        expiry
                            .remove(candidate.index_key.as_slice())
                            .map_err(Error::backend)?;
                    }
                }
                deleted
            };
            transaction.commit().map_err(Error::backend)?;
            Ok(deleted)
        })
        .await?
    }

    async fn close(&self) -> Result<(), Error> {
        let gate = Arc::clone(&self.writer_gate).lock_owned().await;
        let database = self
            .database
            .lock()
            .map_err(|_| Error::BackendState("backend state is unavailable"))?
            .take();
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            drop(database);
            Ok(())
        })
        .await?
    }
}

fn table_is_empty<K: redb::Key + 'static, V: redb::Value + 'static>(
    transaction: &redb::WriteTransaction,
    definition: TableDefinition<'static, K, V>,
) -> Result<bool, Error> {
    let table = transaction.open_table(definition).map_err(Error::backend)?;
    Ok(table
        .iter()
        .map_err(Error::backend)?
        .next()
        .transpose()
        .map_err(Error::backend)?
        .is_none())
}

fn configure_transaction(transaction: &mut redb::WriteTransaction) -> Result<(), Error> {
    transaction
        .set_durability(Durability::Immediate)
        .map_err(Error::backend)?;
    transaction.set_two_phase_commit(true);
    Ok(())
}

fn remove_indexes_for_metadata(
    catalog: &mut redb::Table<&[u8], &[u8]>,
    expiry: &mut redb::Table<&[u8], &[u8]>,
    record_id: &RecordId,
    envelope: &EnvelopeMetadata,
) -> Result<(), Error> {
    let catalog_index = catalog_key(&envelope.tenant_token, record_id);
    catalog
        .remove(catalog_index.as_slice())
        .map_err(Error::backend)?;
    if let Some(expires_at_ms) = envelope.expires_at_ms {
        let index = expiry_index_key(expires_at_ms, record_id, &envelope.revision);
        expiry.remove(index.as_slice()).map_err(Error::backend)?;
    }
    Ok(())
}

fn catalog_key(tenant_token: &TenantToken, record_id: &RecordId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(tenant_token);
    key[32..].copy_from_slice(record_id);
    key
}

fn map_database_error(error: DatabaseError) -> Error {
    match error {
        DatabaseError::DatabaseAlreadyOpen => Error::StoreLocked,
        DatabaseError::UpgradeRequired(_) => Error::UnsupportedFormat,
        other => Error::backend(other),
    }
}

#[cfg(unix)]
fn configure_open_options(options: &mut OpenOptions, is_new: bool) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW);
    if is_new {
        options.mode(0o600);
    }
}

#[cfg(not(unix))]
fn configure_open_options(_: &mut OpenOptions, _: bool) {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::tempdir;

    use super::RedbBackend;
    use crate::backend::Backend;
    use crate::backend::tests::backend_contract;

    #[tokio::test]
    async fn backend_batches_are_atomic_and_snapshot_ordered() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("store");
        let backend = RedbBackend::open(path.clone()).await.expect("open");
        backend_contract(Arc::clone(&backend) as Arc<dyn Backend>).await;
        backend.close().await.expect("close");

        let reopened = RedbBackend::open(path).await.expect("reopen");
        assert_eq!(
            reopened
                .load_or_initialize_header(vec![8, 8, 8])
                .await
                .expect("header"),
            vec![3, 2, 1]
        );
        Arc::clone(&reopened).close().await.expect("close");
    }

    #[tokio::test]
    async fn empty_database_without_header_can_finish_initialization() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("store");
        let interrupted = RedbBackend::open(path.clone()).await.expect("open");
        interrupted.close().await.expect("close before header");

        let recovered = RedbBackend::open(path).await.expect("recover");
        assert_eq!(
            recovered
                .load_or_initialize_header(vec![1, 2, 3])
                .await
                .expect("initialize"),
            vec![1, 2, 3]
        );
        recovered.close().await.expect("close");
    }
}
