use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rusqlite::{
    Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params,
    params_from_iter, types::Value,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, mpsc};

use super::{
    Backend, CatalogEntry, CatalogPage, CleanupCandidate, ExpiryCandidate, ExpiryRecord, Mutation,
    RecordId, TenantToken, decode_put_envelopes,
};
use crate::error::Error;
use crate::format::expiry_index_key;

const HEADER_KEY: &str = "header";
const EXPIRY_BATCH_LIMIT: usize = 10_000;
const READER_CONNECTIONS: usize = 4;
const SQLITE_READ_BATCH_SIZE: usize = 900;
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const INITIALIZATION_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const EXPECTED_TABLES: [&str; 4] = [
    "vaultlet_catalog_v1",
    "vaultlet_expiry_v1",
    "vaultlet_metadata_v1",
    "vaultlet_records_v1",
];
const SCHEMA: &str = r#"
CREATE TABLE vaultlet_metadata_v1 (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE vaultlet_records_v1 (
    record_id BLOB PRIMARY KEY NOT NULL CHECK(length(record_id) = 32),
    envelope BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE vaultlet_catalog_v1 (
    tenant_token BLOB NOT NULL CHECK(length(tenant_token) = 32),
    record_id BLOB NOT NULL CHECK(length(record_id) = 32),
    key_envelope BLOB NOT NULL,
    PRIMARY KEY (tenant_token, record_id),
    UNIQUE (record_id),
    FOREIGN KEY (record_id) REFERENCES vaultlet_records_v1(record_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE vaultlet_expiry_v1 (
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    record_id BLOB NOT NULL CHECK(length(record_id) = 32),
    revision BLOB NOT NULL CHECK(length(revision) = 16),
    PRIMARY KEY (expires_at_ms, record_id, revision),
    FOREIGN KEY (record_id) REFERENCES vaultlet_records_v1(record_id) ON DELETE CASCADE
) WITHOUT ROWID;
"#;

pub(crate) struct SqliteBackend {
    writer: Arc<Mutex<Option<Connection>>>,
    readers: Vec<Arc<Mutex<Option<Connection>>>>,
    available_readers: AsyncMutex<mpsc::Receiver<usize>>,
    return_reader: mpsc::Sender<usize>,
    writer_gate: Arc<AsyncMutex<()>>,
    closed: AtomicBool,
}

struct ReaderLease {
    index: usize,
    sender: mpsc::Sender<usize>,
}

impl Drop for ReaderLease {
    fn drop(&mut self) {
        let _ = self.sender.try_send(self.index);
    }
}

impl SqliteBackend {
    pub(crate) async fn open(path: PathBuf) -> Result<Arc<Self>, Error> {
        tokio::task::spawn_blocking(move || Self::open_blocking(&path)).await?
    }

    fn open_blocking(path: &Path) -> Result<Arc<Self>, Error> {
        ensure_store_file(path)?;
        let path = canonical_store_path(path)?;
        let mut writer = open_connection(&path)?;
        prepare_schema_with_retry(&mut writer)?;
        let readers = (0..READER_CONNECTIONS)
            .map(|_| {
                open_connection(&path).map(|connection| Arc::new(Mutex::new(Some(connection))))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let (return_reader, available_readers) = mpsc::channel(READER_CONNECTIONS);
        for index in 0..READER_CONNECTIONS {
            return_reader
                .try_send(index)
                .map_err(|_| Error::BackendState("reader pool initialization failed"))?;
        }
        Ok(Arc::new(Self {
            writer: Arc::new(Mutex::new(Some(writer))),
            readers,
            available_readers: AsyncMutex::new(available_readers),
            return_reader,
            writer_gate: Arc::new(AsyncMutex::new(())),
            closed: AtomicBool::new(false),
        }))
    }

    async fn writer_context(
        &self,
    ) -> Result<(Arc<Mutex<Option<Connection>>>, OwnedMutexGuard<()>), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let gate = Arc::clone(&self.writer_gate).lock_owned().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        Ok((Arc::clone(&self.writer), gate))
    }

    async fn read_context(&self) -> Result<(Arc<Mutex<Option<Connection>>>, ReaderLease), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let index = self
            .available_readers
            .lock()
            .await
            .recv()
            .await
            .ok_or(Error::Closed)?;
        if self.closed.load(Ordering::Acquire) {
            let _ = self.return_reader.try_send(index);
            return Err(Error::Closed);
        }
        Ok((
            Arc::clone(&self.readers[index]),
            ReaderLease {
                index,
                sender: self.return_reader.clone(),
            },
        ))
    }
}

#[async_trait]
impl Backend for SqliteBackend {
    async fn load_or_initialize_header(&self, candidate: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (writer, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            with_connection(&writer, |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sqlite_error)?;
                let current = transaction
                    .query_row(
                        "SELECT value FROM vaultlet_metadata_v1 WHERE key = ?1",
                        [HEADER_KEY],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .map_err(map_sqlite_error)?;
                if let Some(current) = current {
                    transaction.commit().map_err(map_sqlite_error)?;
                    return Ok(current);
                }
                for table in EXPECTED_TABLES {
                    let query = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
                    if transaction
                        .query_row(&query, [], |row| row.get::<_, bool>(0))
                        .map_err(map_sqlite_error)?
                    {
                        return Err(Error::Integrity);
                    }
                }
                transaction
                    .execute(
                        "INSERT INTO vaultlet_metadata_v1 (key, value) VALUES (?1, ?2)",
                        params![HEADER_KEY, candidate],
                    )
                    .map_err(map_sqlite_error)?;
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(candidate)
            })
        })
        .await?
    }

    async fn replace_header(&self, expected: Vec<u8>, replacement: Vec<u8>) -> Result<bool, Error> {
        let (writer, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            with_connection(&writer, |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sqlite_error)?;
                let changed = transaction
                    .execute(
                        "UPDATE vaultlet_metadata_v1 SET value = ?1 WHERE key = ?2 AND value = ?3",
                        params![replacement, HEADER_KEY, expected],
                    )
                    .map_err(map_sqlite_error)?
                    == 1;
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(changed)
            })
        })
        .await?
    }

    async fn read_many(&self, record_ids: Vec<RecordId>) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let (reader, lease) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            with_connection(&reader, |connection| {
                if record_ids.is_empty() {
                    return Ok(Vec::new());
                }
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Deferred)
                    .map_err(map_sqlite_error)?;
                let mut found = HashMap::with_capacity(record_ids.len());
                for chunk in record_ids.chunks(SQLITE_READ_BATCH_SIZE) {
                    let placeholders = std::iter::repeat_n("?", chunk.len())
                        .collect::<Vec<_>>()
                        .join(",");
                    let query = format!(
                        "SELECT record_id, envelope FROM vaultlet_records_v1 \
                         WHERE record_id IN ({placeholders})"
                    );
                    let mut statement = transaction
                        .prepare_cached(&query)
                        .map_err(map_sqlite_error)?;
                    let rows = statement
                        .query_map(
                            params_from_iter(chunk.iter().map(|value| value.as_slice())),
                            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                        )
                        .map_err(map_sqlite_error)?;
                    for row in rows {
                        let (record_id, envelope) = row.map_err(map_sqlite_error)?;
                        found.insert(
                            RecordId::try_from(record_id).map_err(|_| Error::Integrity)?,
                            envelope,
                        );
                    }
                }
                let values = record_ids
                    .iter()
                    .map(|record_id| found.remove(record_id))
                    .collect();
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(values)
            })
        })
        .await?
    }

    async fn read_one(&self, record_id: RecordId) -> Result<Option<Vec<u8>>, Error> {
        let (reader, lease) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            with_connection(&reader, |connection| {
                connection
                    .query_row(
                        "SELECT envelope FROM vaultlet_records_v1 WHERE record_id = ?1",
                        [record_id.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .map_err(map_sqlite_error)
            })
        })
        .await?
    }

    async fn list_catalog(
        &self,
        tenant_token: TenantToken,
        after: Option<RecordId>,
        limit: usize,
    ) -> Result<CatalogPage, Error> {
        let (reader, lease) = self.read_context().await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            with_connection(&reader, |connection| {
                let fetch_limit = i64::try_from(CatalogPage::fetch_limit(limit)?)
                    .map_err(|_| Error::BackendState("catalogue limit is invalid"))?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Deferred)
                    .map_err(map_sqlite_error)?;
                let entries = {
                    let mut statement = transaction
                        .prepare(
                            "SELECT c.record_id, c.key_envelope
                             FROM vaultlet_catalog_v1 AS c
                             JOIN vaultlet_records_v1 AS r USING (record_id)
                             WHERE c.tenant_token = ?1
                               AND (?2 = 0 OR c.record_id > ?3)
                             ORDER BY c.record_id
                             LIMIT ?4",
                        )
                        .map_err(map_sqlite_error)?;
                    let after_value = after.as_ref().map(<[u8; 32]>::as_slice);
                    let rows = statement
                        .query_map(
                            params![
                                tenant_token.as_slice(),
                                i64::from(after.is_some()),
                                after_value,
                                fetch_limit
                            ],
                            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                        )
                        .map_err(map_sqlite_error)?;
                    rows.map(|row| {
                        let (record_id, key_envelope) = row.map_err(map_sqlite_error)?;
                        Ok(CatalogEntry {
                            record_id: record_id.try_into().map_err(|_| Error::Integrity)?,
                            key_envelope,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                };
                transaction.commit().map_err(map_sqlite_error)?;
                CatalogPage::from_lookahead(entries, limit)
            })
        })
        .await?
    }

    async fn mutate(&self, mutations: Vec<Mutation>) -> Result<Vec<bool>, Error> {
        let (writer, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            with_connection(&writer, |connection| {
                let mutation_count = mutations.len();
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sqlite_error)?;
                let mut results = Vec::with_capacity(mutation_count);
                {
                    let mut delete_expiry = transaction
                        .prepare_cached("DELETE FROM vaultlet_expiry_v1 WHERE record_id = ?1")
                        .map_err(map_sqlite_error)?;
                    let mut put_record = transaction
                        .prepare_cached(
                            "INSERT INTO vaultlet_records_v1 (record_id, envelope)
                             VALUES (?1, ?2)
                             ON CONFLICT(record_id) DO UPDATE SET envelope = excluded.envelope",
                        )
                        .map_err(map_sqlite_error)?;
                    let mut put_catalog = transaction
                        .prepare_cached(
                            "INSERT INTO vaultlet_catalog_v1
                                 (tenant_token, record_id, key_envelope)
                             VALUES (?1, ?2, ?3)
                             ON CONFLICT(record_id) DO UPDATE SET
                                 tenant_token = excluded.tenant_token,
                                 key_envelope = excluded.key_envelope",
                        )
                        .map_err(map_sqlite_error)?;
                    let mut put_expiry = transaction
                        .prepare_cached(
                            "INSERT INTO vaultlet_expiry_v1
                                 (expires_at_ms, record_id, revision)
                             VALUES (?1, ?2, ?3)",
                        )
                        .map_err(map_sqlite_error)?;
                    let mut select_revision = transaction
                        .prepare_cached(
                            "SELECT substr(envelope, 28, 16)
                             FROM vaultlet_records_v1 WHERE record_id = ?1",
                        )
                        .map_err(map_sqlite_error)?;
                    let mut delete_record = transaction
                        .prepare_cached("DELETE FROM vaultlet_records_v1 WHERE record_id = ?1")
                        .map_err(map_sqlite_error)?;
                    for mutation in mutations {
                        match mutation {
                            Mutation::Put {
                                record_id,
                                envelope,
                                tenant_token,
                                key_envelope,
                            } => {
                                let decoded =
                                    decode_put_envelopes(&envelope, &key_envelope, &tenant_token)?;
                                delete_expiry
                                    .execute([record_id.as_slice()])
                                    .map_err(map_sqlite_error)?;
                                put_record
                                    .execute(params![record_id.as_slice(), envelope])
                                    .map_err(map_sqlite_error)?;
                                put_catalog
                                    .execute(params![
                                        tenant_token.as_slice(),
                                        record_id.as_slice(),
                                        key_envelope
                                    ])
                                    .map_err(map_sqlite_error)?;
                                if let Some(expires_at_ms) = decoded.expires_at_ms {
                                    put_expiry
                                        .execute(params![
                                            expires_at_ms,
                                            record_id.as_slice(),
                                            decoded.revision.as_slice()
                                        ])
                                        .map_err(map_sqlite_error)?;
                                }
                                results.push(true);
                            }
                            Mutation::DeleteGuarded {
                                record_id,
                                revision,
                            } => {
                                let matches =
                                    select_revision_statement(&mut select_revision, &record_id)?
                                        .is_some_and(|current| current == revision);
                                if !matches {
                                    return Ok(vec![false; mutation_count]);
                                }
                                delete_record
                                    .execute([record_id.as_slice()])
                                    .map_err(map_sqlite_error)?;
                                results.push(true);
                            }
                            Mutation::DeleteAny { record_id } => {
                                let changed = delete_record
                                    .execute([record_id.as_slice()])
                                    .map_err(map_sqlite_error)?
                                    == 1;
                                results.push(changed);
                            }
                        }
                    }
                }
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(results)
            })
        })
        .await?
    }

    async fn mutate_one(&self, mutation: Mutation) -> Result<bool, Error> {
        let (writer, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            with_connection(&writer, |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sqlite_error)?;
                let changed = match mutation {
                    Mutation::Put {
                        record_id,
                        envelope,
                        tenant_token,
                        key_envelope,
                    } => {
                        let decoded =
                            decode_put_envelopes(&envelope, &key_envelope, &tenant_token)?;
                        transaction
                            .execute(
                                "DELETE FROM vaultlet_expiry_v1 WHERE record_id = ?1",
                                [record_id.as_slice()],
                            )
                            .map_err(map_sqlite_error)?;
                        transaction
                            .execute(
                                "INSERT INTO vaultlet_records_v1 (record_id, envelope)
                                 VALUES (?1, ?2)
                                 ON CONFLICT(record_id)
                                 DO UPDATE SET envelope = excluded.envelope",
                                params![record_id.as_slice(), envelope],
                            )
                            .map_err(map_sqlite_error)?;
                        transaction
                            .execute(
                                "INSERT INTO vaultlet_catalog_v1
                                     (tenant_token, record_id, key_envelope)
                                 VALUES (?1, ?2, ?3)
                                 ON CONFLICT(record_id) DO UPDATE SET
                                     tenant_token = excluded.tenant_token,
                                     key_envelope = excluded.key_envelope",
                                params![
                                    tenant_token.as_slice(),
                                    record_id.as_slice(),
                                    key_envelope
                                ],
                            )
                            .map_err(map_sqlite_error)?;
                        if let Some(expires_at_ms) = decoded.expires_at_ms {
                            transaction
                                .execute(
                                    "INSERT INTO vaultlet_expiry_v1
                                         (expires_at_ms, record_id, revision)
                                     VALUES (?1, ?2, ?3)",
                                    params![
                                        expires_at_ms,
                                        record_id.as_slice(),
                                        decoded.revision.as_slice()
                                    ],
                                )
                                .map_err(map_sqlite_error)?;
                        }
                        true
                    }
                    Mutation::DeleteGuarded {
                        record_id,
                        revision,
                    } => {
                        let current = transaction
                            .query_row(
                                "SELECT substr(envelope, 28, 16)
                                 FROM vaultlet_records_v1 WHERE record_id = ?1",
                                [record_id.as_slice()],
                                |row| row.get::<_, Vec<u8>>(0),
                            )
                            .optional()
                            .map_err(map_sqlite_error)?;
                        let matches = current
                            .and_then(|value| value.try_into().ok())
                            .is_some_and(|current: [u8; 16]| current == revision);
                        if matches {
                            transaction
                                .execute(
                                    "DELETE FROM vaultlet_records_v1 WHERE record_id = ?1",
                                    [record_id.as_slice()],
                                )
                                .map_err(map_sqlite_error)?;
                        }
                        matches
                    }
                    Mutation::DeleteAny { record_id } => {
                        transaction
                            .execute(
                                "DELETE FROM vaultlet_records_v1 WHERE record_id = ?1",
                                [record_id.as_slice()],
                            )
                            .map_err(map_sqlite_error)?
                            == 1
                    }
                };
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(changed)
            })
        })
        .await?
    }

    async fn scan_due(&self, now_ms: i64, limit: usize) -> Result<Vec<ExpiryCandidate>, Error> {
        let (reader, lease) = self.read_context().await?;
        let limit = limit.min(EXPIRY_BATCH_LIMIT);
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            with_connection(&reader, |connection| {
                let mut statement = connection
                    .prepare(
                        "SELECT expires_at_ms, record_id, revision
                         FROM vaultlet_expiry_v1
                         WHERE expires_at_ms <= ?1
                         ORDER BY expires_at_ms, record_id, revision
                         LIMIT ?2",
                    )
                    .map_err(map_sqlite_error)?;
                let rows = statement
                    .query_map(
                        params![now_ms, i64::try_from(limit).map_err(|_| Error::Integrity)?],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                    .map_err(map_sqlite_error)?;
                rows.map(|row| {
                    let (expires_at_ms, record_id, revision) = row.map_err(map_sqlite_error)?;
                    let record_id: RecordId = record_id.try_into().map_err(|_| Error::Integrity)?;
                    let revision: [u8; 16] = revision.try_into().map_err(|_| Error::Integrity)?;
                    Ok(ExpiryCandidate {
                        index_key: expiry_index_key(expires_at_ms, &record_id, &revision),
                        expires_at_ms,
                        record_id,
                        revision,
                    })
                })
                .collect()
            })
        })
        .await?
    }

    async fn scan_due_records(
        &self,
        now_ms: i64,
        record_limit: usize,
        byte_limit: usize,
    ) -> Result<Vec<ExpiryRecord>, Error> {
        let (reader, lease) = self.read_context().await?;
        let record_limit = record_limit.min(EXPIRY_BATCH_LIMIT);
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            with_connection(&reader, |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Deferred)
                    .map_err(map_sqlite_error)?;
                let mut records = Vec::with_capacity(record_limit);
                let mut total_bytes = 0_usize;
                {
                    let mut statement = transaction
                        .prepare_cached(
                            "SELECT e.expires_at_ms, e.record_id, e.revision, r.envelope
                             FROM vaultlet_expiry_v1 AS e
                             LEFT JOIN vaultlet_records_v1 AS r
                               ON r.record_id = e.record_id
                             WHERE e.expires_at_ms <= ?1
                             ORDER BY e.expires_at_ms, e.record_id, e.revision
                             LIMIT ?2",
                        )
                        .map_err(map_sqlite_error)?;
                    let mut rows = statement
                        .query(params![
                            now_ms,
                            i64::try_from(record_limit).map_err(|_| Error::Integrity)?
                        ])
                        .map_err(map_sqlite_error)?;
                    while let Some(row) = rows.next().map_err(map_sqlite_error)? {
                        let expires_at_ms = row.get::<_, i64>(0).map_err(map_sqlite_error)?;
                        let record_id: RecordId = row
                            .get::<_, Vec<u8>>(1)
                            .map_err(map_sqlite_error)?
                            .try_into()
                            .map_err(|_| Error::Integrity)?;
                        let revision: [u8; 16] = row
                            .get::<_, Vec<u8>>(2)
                            .map_err(map_sqlite_error)?
                            .try_into()
                            .map_err(|_| Error::Integrity)?;
                        let envelope =
                            row.get::<_, Option<Vec<u8>>>(3).map_err(map_sqlite_error)?;
                        let next_bytes = envelope.as_ref().map_or(0, Vec::len);
                        if !records.is_empty()
                            && total_bytes.saturating_add(next_bytes) > byte_limit
                        {
                            break;
                        }
                        total_bytes = total_bytes.saturating_add(next_bytes);
                        records.push(ExpiryRecord {
                            candidate: ExpiryCandidate {
                                index_key: expiry_index_key(expires_at_ms, &record_id, &revision),
                                expires_at_ms,
                                record_id,
                                revision,
                            },
                            envelope,
                        });
                    }
                }
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(records)
            })
        })
        .await?
    }

    async fn cleanup_candidates(&self, candidates: Vec<CleanupCandidate>) -> Result<usize, Error> {
        let (writer, gate) = self.writer_context().await?;
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            with_connection(&writer, |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(map_sqlite_error)?;
                if candidates.is_empty() {
                    transaction.commit().map_err(map_sqlite_error)?;
                    return Ok(0);
                }
                let expiry_placeholders = std::iter::repeat_n("(?, ?, ?)", candidates.len())
                    .collect::<Vec<_>>()
                    .join(",");
                let expiry_query = format!(
                    "DELETE FROM vaultlet_expiry_v1
                     WHERE (expires_at_ms, record_id, revision)
                     IN ({expiry_placeholders})"
                );
                let expiry_values = candidates
                    .iter()
                    .flat_map(|cleanup| {
                        let candidate = &cleanup.candidate;
                        [
                            Value::Integer(candidate.expires_at_ms),
                            Value::Blob(candidate.record_id.to_vec()),
                            Value::Blob(candidate.revision.to_vec()),
                        ]
                    })
                    .collect::<Vec<_>>();
                transaction
                    .prepare_cached(&expiry_query)
                    .map_err(map_sqlite_error)?
                    .execute(params_from_iter(expiry_values))
                    .map_err(map_sqlite_error)?;

                let current = candidates
                    .iter()
                    .filter(|cleanup| cleanup.delete_current)
                    .collect::<Vec<_>>();
                let deleted = if current.is_empty() {
                    0
                } else {
                    let record_placeholders = std::iter::repeat_n("(?, ?)", current.len())
                        .collect::<Vec<_>>()
                        .join(",");
                    let record_query = format!(
                        "DELETE FROM vaultlet_records_v1
                         WHERE (record_id, substr(envelope, 28, 16))
                         IN ({record_placeholders})"
                    );
                    let record_values = current
                        .iter()
                        .flat_map(|cleanup| {
                            [
                                Value::Blob(cleanup.candidate.record_id.to_vec()),
                                Value::Blob(cleanup.candidate.revision.to_vec()),
                            ]
                        })
                        .collect::<Vec<_>>();
                    transaction
                        .prepare_cached(&record_query)
                        .map_err(map_sqlite_error)?
                        .execute(params_from_iter(record_values))
                        .map_err(map_sqlite_error)?
                };
                transaction.commit().map_err(map_sqlite_error)?;
                Ok(deleted)
            })
        })
        .await?
    }

    async fn close(&self) -> Result<(), Error> {
        let _gate = Arc::clone(&self.writer_gate).lock_owned().await;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        take_connection(&self.writer)?;
        for reader in &self.readers {
            take_connection(reader)?;
        }
        Ok(())
    }
}

fn ensure_store_file(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            configure_open_options(&mut options);
            match options.open(path) {
                Ok(file) => validate_metadata(&file.metadata().map_err(Error::backend)?),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(path).map_err(Error::backend)?;
                    validate_metadata(&metadata)
                }
                Err(error) => Err(Error::backend(error)),
            }
        }
        Err(error) => Err(Error::backend(error)),
    }
}

fn validate_metadata(metadata: &fs::Metadata) -> Result<(), Error> {
    if metadata.file_type().is_symlink() {
        return Err(Error::Configuration("store paths cannot be symbolic links"));
    }
    if !metadata.is_file() {
        return Err(Error::Configuration("store path must be a regular file"));
    }
    Ok(())
}

fn canonical_store_path(path: &Path) -> Result<PathBuf, Error> {
    let file_name = path
        .file_name()
        .ok_or(Error::Configuration("store path must name a file"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical = parent
        .canonicalize()
        .map_err(Error::backend)?
        .join(file_name);
    validate_metadata(&fs::symlink_metadata(&canonical).map_err(Error::backend)?)?;
    Ok(canonical)
}

fn open_connection(path: &Path) -> Result<Connection, Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags).map_err(map_sqlite_error)?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(map_sqlite_error)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA synchronous = FULL;
             PRAGMA cache_size = -8192;
             PRAGMA mmap_size = 268435456;",
        )
        .map_err(map_sqlite_error)?;
    Ok(connection)
}

fn prepare_schema(connection: &mut Connection) -> Result<(), Error> {
    let current_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(map_sqlite_error)?;
    let journal_mode = if current_mode.eq_ignore_ascii_case("wal") {
        current_mode
    } else {
        connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_sqlite_error)?
    };
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(Error::StoreLocked);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    let objects = {
        let mut statement = transaction
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(map_sqlite_error)?
            .map(|row| row.map_err(map_sqlite_error))
            .collect::<Result<BTreeSet<_>, Error>>()?
    };
    let expected = EXPECTED_TABLES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if objects.is_empty() {
        transaction
            .execute_batch(SCHEMA)
            .map_err(map_sqlite_error)?;
    } else if objects != expected {
        return Err(Error::Integrity);
    } else {
        validate_schema(&transaction)?;
    }
    transaction.commit().map_err(map_sqlite_error)
}

fn prepare_schema_with_retry(connection: &mut Connection) -> Result<(), Error> {
    connection
        .busy_timeout(INITIALIZATION_BUSY_TIMEOUT)
        .map_err(map_sqlite_error)?;
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        match prepare_schema(connection) {
            Ok(()) => {
                connection
                    .busy_timeout(BUSY_TIMEOUT)
                    .map_err(map_sqlite_error)?;
                return Ok(());
            }
            Err(Error::StoreLocked) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    transaction
        .prepare("SELECT key, value FROM vaultlet_metadata_v1 LIMIT 0")
        .and_then(|_| {
            transaction.prepare("SELECT record_id, envelope FROM vaultlet_records_v1 LIMIT 0")
        })
        .and_then(|_| {
            transaction.prepare(
                "SELECT tenant_token, record_id, key_envelope FROM vaultlet_catalog_v1 LIMIT 0",
            )
        })
        .and_then(|_| {
            transaction.prepare(
                "SELECT expires_at_ms, record_id, revision FROM vaultlet_expiry_v1 LIMIT 0",
            )
        })
        .map(|_| ())
        .map_err(|_| Error::Integrity)
}

fn select_revision_statement(
    statement: &mut rusqlite::Statement<'_>,
    record_id: &RecordId,
) -> Result<Option<[u8; 16]>, Error> {
    statement
        .query_row([record_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(map_sqlite_error)
        .and_then(|revision| {
            revision
                .map(|value| value.try_into().map_err(|_| Error::Integrity))
                .transpose()
        })
}

fn with_connection<T>(
    connection: &Mutex<Option<Connection>>,
    operation: impl FnOnce(&mut Connection) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut guard = connection
        .lock()
        .map_err(|_| Error::BackendState("backend state is unavailable"))?;
    operation(guard.as_mut().ok_or(Error::Closed)?)
}

fn take_connection(connection: &Mutex<Option<Connection>>) -> Result<(), Error> {
    connection
        .lock()
        .map_err(|_| Error::BackendState("backend state is unavailable"))?
        .take();
    Ok(())
}

fn map_sqlite_error(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) =>
        {
            Error::Integrity
        }
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            Error::StoreLocked
        }
        other => Error::backend(other),
    }
}

#[cfg(unix)]
fn configure_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
}

#[cfg(not(unix))]
fn configure_open_options(_: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::tempdir;

    use super::SqliteBackend;
    use crate::backend::Backend;
    use crate::backend::tests::backend_contract;

    #[tokio::test]
    async fn backend_batches_are_atomic_and_snapshot_ordered() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("store");
        let backend = SqliteBackend::open(path.clone()).await.expect("open");
        backend_contract(Arc::clone(&backend) as Arc<dyn Backend>).await;
        backend.close().await.expect("close");

        let reopened = SqliteBackend::open(path).await.expect("reopen");
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
        let interrupted = SqliteBackend::open(path.clone()).await.expect("open");
        interrupted.close().await.expect("close before header");

        let recovered = SqliteBackend::open(path).await.expect("recover");
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
