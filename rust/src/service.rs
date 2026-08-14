use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rayon::prelude::*;
use tokio::sync::{
    Mutex, Notify, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock, Semaphore, oneshot,
};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{
    Backend, CatalogEntry, CleanupCandidate, ExpiryCandidate, Mutation, RecordId, RedbBackend,
    RedisBackend, RedisConfig, SqliteBackend,
};
use crate::crypto::{KeySchedule, MasterKey, RandomSource, SystemRandom, TenantCryptoContext};
use crate::error::Error;
use crate::format::{Header, MAX_VALUE_SIZE, PlaintextBuffer, ValueKind, expiry_index_key};
use crate::json::JsonDocument;

const OPEN: u8 = 0;
const CLOSING: u8 = 1;
const CLOSED: u8 = 2;
const IDENTIFIER_LIMIT: usize = 1024;
const PURGE_BATCH_SIZE: usize = 256;
const PURGE_BATCH_BYTES: usize =
    crate::format::MAX_VALUE_SIZE + 16 + crate::format::RECORD_PREFIX_SIZE;
const DELETE_RETRIES: usize = 32;
const BLOCKING_OPERATION_LIMIT: usize = 32;
const PARALLEL_BATCH_ITEMS: usize = 8;
const PARALLEL_BATCH_BYTES: usize = 1024 * 1024;
const ITEM_RANDOM_BYTES: usize = 16 + 24 + 24;
const CATALOG_CURSOR_PREFIX: &str = "v1.";
const CATALOG_CURSOR_BYTES: usize = 64;
pub(crate) const MAX_BATCH_ITEMS: usize = 10_000;
pub(crate) const MAX_BATCH_VALUE_BYTES: usize = MAX_VALUE_SIZE;
pub(crate) const MAX_KEY_LIST_LIMIT: usize = 10_000;

#[derive(Clone, Copy)]
pub(crate) enum StorageEngine {
    Redb,
    Sqlite,
}

trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<i64, Error>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<i64, Error> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::BackendState("system clock is before the Unix epoch"))?;
        i64::try_from(duration.as_millis())
            .map_err(|_| Error::BackendState("system clock is outside the supported range"))
    }
}

pub(crate) struct SetItem {
    pub(crate) key: String,
    pub(crate) value: PlaintextBuffer,
    pub(crate) kind: ValueKind,
    pub(crate) expires_at_ms: Option<i64>,
}

pub(crate) struct Entry {
    pub(crate) value: Zeroizing<Vec<u8>>,
    value_offset: usize,
    pub(crate) expires_at_ms: Option<i64>,
}

impl Entry {
    pub(crate) fn value(&self) -> &[u8] {
        &self.value[self.value_offset..]
    }

    pub(crate) fn into_buffer(self) -> (Zeroizing<Vec<u8>>, usize) {
        (self.value, self.value_offset)
    }

    pub(crate) fn from_buffer(value: Zeroizing<Vec<u8>>, value_offset: usize) -> Self {
        Self {
            value,
            value_offset,
            expires_at_ms: None,
        }
    }
}

pub(crate) struct EntryMetadata {
    pub(crate) kind: ValueKind,
    pub(crate) encoded_size: u64,
    pub(crate) expires_at_ms: Option<i64>,
}

struct DecodedEntry {
    entry: Entry,
    revision: [u8; 16],
}

pub(crate) struct Service {
    backend: Arc<dyn Backend>,
    keys: Arc<KeySchedule>,
    data_key: MasterKey,
    header: Mutex<Vec<u8>>,
    rotation_gate: Mutex<()>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
    state: AtomicU8,
    lifecycle: Arc<RwLock<()>>,
    blocking_gate: Arc<Semaphore>,
    closed_notify: Notify,
    worker_stop: Mutex<Option<oneshot::Sender<()>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    cleanup_interval: Duration,
}

impl Service {
    pub(crate) async fn open(
        path: PathBuf,
        master: MasterKey,
        cleanup_interval: Duration,
        engine: StorageEngine,
    ) -> Result<Arc<Self>, Error> {
        Self::open_with_boundaries(
            path,
            master,
            cleanup_interval,
            engine,
            Arc::new(SystemClock),
            Arc::new(SystemRandom),
        )
        .await
    }

    pub(crate) async fn open_redis(
        config: RedisConfig,
        master: MasterKey,
        cleanup_interval: Duration,
    ) -> Result<Arc<Self>, Error> {
        let backend: Arc<dyn Backend> = RedisBackend::open(config).await?;
        Self::open_with_backend(
            backend,
            master,
            cleanup_interval,
            Arc::new(SystemClock),
            Arc::new(SystemRandom),
        )
        .await
    }

    async fn open_with_boundaries(
        path: PathBuf,
        master: MasterKey,
        cleanup_interval: Duration,
        engine: StorageEngine,
        clock: Arc<dyn Clock>,
        random: Arc<dyn RandomSource>,
    ) -> Result<Arc<Self>, Error> {
        let backend: Arc<dyn Backend> = match engine {
            StorageEngine::Redb => RedbBackend::open(path).await?,
            StorageEngine::Sqlite => SqliteBackend::open(path).await?,
        };
        Self::open_with_backend(backend, master, cleanup_interval, clock, random).await
    }

    async fn open_with_backend(
        backend: Arc<dyn Backend>,
        master: MasterKey,
        cleanup_interval: Duration,
        clock: Arc<dyn Clock>,
        random: Arc<dyn RandomSource>,
    ) -> Result<Arc<Self>, Error> {
        let (candidate, candidate_schedule, candidate_data_key) =
            KeySchedule::create_header(&master, random.as_ref())?;
        let candidate = candidate.encode();
        let stored_header = backend.load_or_initialize_header(candidate.clone()).await?;
        let (schedule, data_key) = if stored_header == candidate {
            (candidate_schedule, candidate_data_key)
        } else {
            KeySchedule::from_header(&master, &Header::decode(&stored_header)?)?
        };
        drop(master);
        let service = Arc::new(Self {
            backend,
            keys: Arc::new(schedule),
            data_key,
            header: Mutex::new(stored_header),
            rotation_gate: Mutex::new(()),
            clock,
            random,
            state: AtomicU8::new(OPEN),
            lifecycle: Arc::new(RwLock::new(())),
            blocking_gate: Arc::new(Semaphore::new(BLOCKING_OPERATION_LIMIT)),
            closed_notify: Notify::new(),
            worker_stop: Mutex::new(None),
            worker: Mutex::new(None),
            cleanup_interval,
        });
        service.start_worker().await;
        Ok(service)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) != OPEN
    }

    pub(crate) fn tenant(&self, tenant: &str) -> Result<Arc<TenantCryptoContext>, Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        validate_identifier(tenant)?;
        self.keys.tenant_context(tenant).map(Arc::new)
    }

    async fn enter(&self) -> Result<OwnedRwLockReadGuard<()>, Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let guard = Arc::clone(&self.lifecycle).read_owned().await;
        if self.is_closed() {
            return Err(Error::Closed);
        }
        Ok(guard)
    }

    async fn blocking_permit(&self) -> Result<OwnedSemaphorePermit, Error> {
        Arc::clone(&self.blocking_gate)
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)
    }

    async fn start_worker(self: &Arc<Self>) {
        if self.cleanup_interval.is_zero() {
            return;
        }
        let (sender, receiver) = oneshot::channel();
        *self.worker_stop.lock().await = Some(sender);
        let weak = Arc::downgrade(self);
        let interval = self.cleanup_interval;
        *self.worker.lock().await = Some(tokio::spawn(expiry_worker(weak, receiver, interval)));
    }

    pub(crate) async fn close(&self) -> Result<(), Error> {
        if self
            .state
            .compare_exchange(OPEN, CLOSING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            loop {
                let notified = self.closed_notify.notified();
                if self.state.load(Ordering::Acquire) != CLOSING {
                    break;
                }
                notified.await;
            }
            return Ok(());
        }

        if let Some(sender) = self.worker_stop.lock().await.take() {
            let _ = sender.send(());
        }
        if let Some(worker) = self.worker.lock().await.take() {
            let _ = worker.await;
        }
        let lifecycle = Arc::clone(&self.lifecycle).write_owned().await;
        let result = self.backend.close().await;
        drop(lifecycle);
        self.state.store(CLOSED, Ordering::Release);
        self.closed_notify.notify_waiters();
        result
    }

    pub(crate) async fn set(
        &self,
        tenant: Arc<TenantCryptoContext>,
        item: SetItem,
    ) -> Result<(), Error> {
        let _operation = self.enter().await?;
        validate_identifier(&item.key)?;
        validate_expiry(item.expires_at_ms)?;
        let random = Arc::clone(&self.random);
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let mutation = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut randomness = [0_u8; ITEM_RANDOM_BYTES];
            random.fill(&mut randomness)?;
            encrypt_item(tenant.as_ref(), item, now_ms, &randomness)
        })
        .await??;
        self.backend.mutate_one(mutation).await?;
        Ok(())
    }

    pub(crate) async fn set_many(
        &self,
        tenant: Arc<TenantCryptoContext>,
        items: Vec<SetItem>,
    ) -> Result<(), Error> {
        let _operation = self.enter().await?;
        validate_set_batch(&items)?;
        if items.is_empty() {
            return Ok(());
        }
        ensure_unique(items.iter().map(|item| item.key.as_str()))?;
        for item in &items {
            validate_identifier(&item.key)?;
            validate_expiry(item.expires_at_ms)?;
        }
        let random = Arc::clone(&self.random);
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let mutations = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let total_bytes = items.iter().map(|item| item.value.len()).sum::<usize>();
            let mut randomness = vec![0_u8; items.len() * ITEM_RANDOM_BYTES];
            random.fill(&mut randomness)?;
            if items.len() >= PARALLEL_BATCH_ITEMS && total_bytes >= PARALLEL_BATCH_BYTES {
                items
                    .into_par_iter()
                    .enumerate()
                    .map(|(index, item)| {
                        encrypt_item(
                            tenant.as_ref(),
                            item,
                            now_ms,
                            &randomness[index * ITEM_RANDOM_BYTES..(index + 1) * ITEM_RANDOM_BYTES],
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()
            } else {
                items
                    .into_iter()
                    .enumerate()
                    .map(|(index, item)| {
                        encrypt_item(
                            tenant.as_ref(),
                            item,
                            now_ms,
                            &randomness[index * ITEM_RANDOM_BYTES..(index + 1) * ITEM_RANDOM_BYTES],
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()
            }
        })
        .await??;
        self.backend.mutate(mutations).await?;
        Ok(())
    }

    pub(crate) async fn get_many(
        &self,
        tenant: Arc<TenantCryptoContext>,
        keys: Vec<String>,
        expected_kind: Option<ValueKind>,
    ) -> Result<(Vec<String>, Vec<Option<Entry>>), Error> {
        let _operation = self.enter().await?;
        validate_batch_count(keys.len())?;
        ensure_unique(keys.iter().map(String::as_str))?;
        for key in &keys {
            validate_identifier(key)?;
        }
        let record_ids = keys
            .iter()
            .map(|key| tenant.record_id(key))
            .collect::<Result<Vec<_>, _>>()?;
        let raw = self.backend.read_many(record_ids.clone()).await?;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (decoded, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            decode_entries(tenant, record_ids, raw, expected_kind, now_ms)
        })
        .await??;
        if !expired.is_empty() {
            self.backend
                .cleanup_candidates(
                    expired
                        .into_iter()
                        .map(|candidate| CleanupCandidate {
                            candidate,
                            delete_current: true,
                        })
                        .collect(),
                )
                .await?;
        }
        Ok((
            keys,
            decoded
                .into_iter()
                .map(|value| value.map(|value| value.entry))
                .collect(),
        ))
    }

    pub(crate) async fn get(
        &self,
        tenant: Arc<TenantCryptoContext>,
        key: String,
        expected_kind: ValueKind,
    ) -> Result<Option<Entry>, Error> {
        let _operation = self.enter().await?;
        validate_identifier(&key)?;
        let record_id = tenant.record_id(&key)?;
        let raw = self.backend.read_one(record_id).await?;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (decoded, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            decode_entry(tenant, record_id, raw, Some(expected_kind), now_ms)
        })
        .await??;
        if let Some(candidate) = expired {
            self.backend
                .cleanup_candidates(vec![CleanupCandidate {
                    candidate,
                    delete_current: true,
                }])
                .await?;
        }
        Ok(decoded.map(|value| value.entry))
    }

    pub(crate) async fn get_json(
        &self,
        tenant: Arc<TenantCryptoContext>,
        key: String,
    ) -> Result<Option<JsonDocument>, Error> {
        let _operation = self.enter().await?;
        validate_identifier(&key)?;
        let record_id = tenant.record_id(&key)?;
        let raw = self.backend.read_one(record_id).await?;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (document, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (decoded, expired) =
                decode_entry(tenant, record_id, raw, Some(ValueKind::Json), now_ms)?;
            let document = decoded
                .map(|value| JsonDocument::from_entry(value.entry))
                .transpose()?;
            Ok::<_, Error>((document, expired))
        })
        .await??;
        if let Some(candidate) = expired {
            self.backend
                .cleanup_candidates(vec![CleanupCandidate {
                    candidate,
                    delete_current: true,
                }])
                .await?;
        }
        Ok(document)
    }

    pub(crate) async fn get_many_json(
        &self,
        tenant: Arc<TenantCryptoContext>,
        keys: Vec<String>,
    ) -> Result<(Vec<String>, Vec<Option<JsonDocument>>), Error> {
        let _operation = self.enter().await?;
        ensure_unique(keys.iter().map(String::as_str))?;
        for key in &keys {
            validate_identifier(key)?;
        }
        let record_ids = keys
            .iter()
            .map(|key| tenant.record_id(key))
            .collect::<Result<Vec<_>, _>>()?;
        let raw = self.backend.read_many(record_ids.clone()).await?;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (documents, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (decoded, expired) =
                decode_entries(tenant, record_ids, raw, Some(ValueKind::Json), now_ms)?;
            let documents = decoded
                .into_iter()
                .map(|value| {
                    value
                        .map(|value| JsonDocument::from_entry(value.entry))
                        .transpose()
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok::<_, Error>((documents, expired))
        })
        .await??;
        if !expired.is_empty() {
            self.backend
                .cleanup_candidates(
                    expired
                        .into_iter()
                        .map(|candidate| CleanupCandidate {
                            candidate,
                            delete_current: true,
                        })
                        .collect(),
                )
                .await?;
        }
        Ok((keys, documents))
    }

    pub(crate) async fn metadata(
        &self,
        tenant: Arc<TenantCryptoContext>,
        key: String,
    ) -> Result<Option<EntryMetadata>, Error> {
        let _operation = self.enter().await?;
        validate_identifier(&key)?;
        let record_id = tenant.record_id(&key)?;
        let raw = self.backend.read_one(record_id).await?;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (metadata, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            authenticate_entry(tenant, record_id, raw, now_ms)
        })
        .await??;
        if let Some(candidate) = expired {
            self.backend
                .cleanup_candidates(vec![CleanupCandidate {
                    candidate,
                    delete_current: true,
                }])
                .await?;
        }
        Ok(metadata)
    }

    pub(crate) async fn exists(
        &self,
        tenant: Arc<TenantCryptoContext>,
        key: String,
    ) -> Result<bool, Error> {
        self.metadata(tenant, key)
            .await
            .map(|value| value.is_some())
    }

    pub(crate) async fn list_keys(
        &self,
        tenant: Arc<TenantCryptoContext>,
        cursor: Option<String>,
        limit: usize,
    ) -> Result<(Vec<String>, bool, Option<String>), Error> {
        if !(1..=MAX_KEY_LIST_LIMIT).contains(&limit) {
            return Err(Error::Configuration(
                "key list limit must be between 1 and 10000",
            ));
        }
        let tenant_token = *tenant.tenant_token();
        let after = decode_catalog_cursor(cursor.as_deref(), tenant.as_ref())?;
        let _operation = self.enter().await?;
        let page = self
            .backend
            .list_catalog(tenant_token, after, limit)
            .await?;
        let next_cursor = if page.has_more {
            let record_id = page
                .entries
                .last()
                .ok_or(Error::BackendState("catalogue page is invalid"))?
                .record_id;
            Some(encode_catalog_cursor(tenant.as_ref(), &record_id))
        } else {
            None
        };
        let entries = page.entries;
        let now_ms = self.clock.now_ms()?;
        let permit = self.blocking_permit().await?;
        let (mut keys, expired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            decode_catalog(tenant, entries, now_ms)
        })
        .await??;
        if !expired.is_empty() {
            self.backend
                .cleanup_candidates(
                    expired
                        .into_iter()
                        .map(|candidate| CleanupCandidate {
                            candidate,
                            delete_current: true,
                        })
                        .collect(),
                )
                .await?;
        }
        keys.sort_unstable();
        Ok((keys, next_cursor.is_some(), next_cursor))
    }

    pub(crate) async fn rotate_master_key(&self, new_master: MasterKey) -> Result<(), Error> {
        let _operation = self.enter().await?;
        let _rotation = self.rotation_gate.lock().await;
        let expected = self.header.lock().await.clone();
        let current = Header::decode(&expected)?;
        let replacement = KeySchedule::rotate_header(
            &current,
            &self.data_key,
            &new_master,
            self.random.as_ref(),
        )?
        .encode();
        drop(new_master);
        if !self
            .backend
            .replace_header(expected, replacement.clone())
            .await?
        {
            return Err(Error::BackendState(
                "the store header changed in another process; reopen before rotating",
            ));
        }
        *self.header.lock().await = replacement;
        Ok(())
    }

    pub(crate) async fn delete_many(
        &self,
        tenant: Arc<TenantCryptoContext>,
        keys: Vec<String>,
    ) -> Result<usize, Error> {
        let _operation = self.enter().await?;
        validate_batch_count(keys.len())?;
        ensure_unique(keys.iter().map(String::as_str))?;
        for key in &keys {
            validate_identifier(key)?;
        }
        if keys.is_empty() {
            return Ok(0);
        }
        let record_ids = keys
            .iter()
            .map(|key| tenant.record_id(key))
            .collect::<Result<Vec<_>, _>>()?;
        for _ in 0..DELETE_RETRIES {
            let raw = self.backend.read_many(record_ids.clone()).await?;
            let now_ms = self.clock.now_ms()?;
            let tenant_copy = Arc::clone(&tenant);
            let ids_copy = record_ids.clone();
            let permit = self.blocking_permit().await?;
            let (mut decoded, expired) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                decode_entries(tenant_copy, ids_copy, raw, None, now_ms)
            })
            .await??;
            let live_count = decoded
                .iter()
                .filter(|value| {
                    value.as_ref().is_some_and(|value| {
                        value
                            .entry
                            .expires_at_ms
                            .is_none_or(|expiry| expiry > now_ms)
                    })
                })
                .count();
            let mut mutations = record_ids
                .iter()
                .zip(decoded.iter())
                .filter_map(|(record_id, value)| {
                    value.as_ref().map(|value| Mutation::DeleteGuarded {
                        record_id: *record_id,
                        revision: value.revision,
                    })
                })
                .collect::<Vec<_>>();
            mutations.extend(
                expired
                    .into_iter()
                    .map(|candidate| Mutation::DeleteGuarded {
                        record_id: candidate.record_id,
                        revision: candidate.revision,
                    }),
            );
            for value in decoded.iter_mut().flatten() {
                value.entry.value.zeroize();
            }
            if mutations.is_empty() {
                return Ok(0);
            }
            let results = self.backend.mutate(mutations).await?;
            if results.iter().all(|result| *result) {
                return Ok(live_count);
            }
        }
        Err(Error::BackendState(
            "concurrent writes prevented a consistent delete",
        ))
    }

    pub(crate) async fn delete(
        &self,
        tenant: Arc<TenantCryptoContext>,
        key: String,
    ) -> Result<bool, Error> {
        let _operation = self.enter().await?;
        validate_identifier(&key)?;
        let record_id = tenant.record_id(&key)?;
        for _ in 0..DELETE_RETRIES {
            let raw = self.backend.read_one(record_id).await?;
            let now_ms = self.clock.now_ms()?;
            let tenant_copy = Arc::clone(&tenant);
            let permit = self.blocking_permit().await?;
            let (mut decoded, expired) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                decode_entry(tenant_copy, record_id, raw, None, now_ms)
            })
            .await??;
            let (revision, was_live) = match (&decoded, &expired) {
                (Some(value), _) => (value.revision, true),
                (None, Some(candidate)) => (candidate.revision, false),
                (None, None) => return Ok(false),
            };
            if let Some(value) = &mut decoded {
                value.entry.value.zeroize();
            }
            let changed = self
                .backend
                .mutate_one(Mutation::DeleteGuarded {
                    record_id,
                    revision,
                })
                .await?;
            if changed {
                return Ok(was_live);
            }
        }
        Err(Error::BackendState(
            "concurrent writes prevented a consistent delete",
        ))
    }

    pub(crate) async fn purge_expired(&self) -> Result<usize, Error> {
        let _operation = self.enter().await?;
        self.purge_expired_inner().await
    }

    async fn purge_expired_inner(&self) -> Result<usize, Error> {
        let now_ms = self.clock.now_ms()?;
        let mut total = 0;
        loop {
            let records = self
                .backend
                .scan_due_records(now_ms, PURGE_BATCH_SIZE, PURGE_BATCH_BYTES)
                .await?;
            if records.is_empty() {
                return Ok(total);
            }
            let schedule = Arc::clone(&self.keys);
            let permit = self.blocking_permit().await?;
            let cleanup = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut contexts = HashMap::new();
                let mut cleanup = records
                    .iter()
                    .map(|record| CleanupCandidate {
                        candidate: record.candidate.clone(),
                        delete_current: false,
                    })
                    .collect::<Vec<_>>();
                let mut authenticated = Vec::new();
                let mut total_bytes = 0_usize;
                for (index, record) in records.into_iter().enumerate() {
                    let Some(raw) = record.envelope else {
                        continue;
                    };
                    let metadata = crate::format::EnvelopeRef::parse(&raw)?.metadata();
                    if metadata.revision != record.candidate.revision {
                        continue;
                    }
                    let context = match contexts.get(&metadata.tenant_token) {
                        Some(context) => Arc::clone(context),
                        None => {
                            let context = Arc::new(
                                schedule.tenant_context_from_token(metadata.tenant_token)?,
                            );
                            contexts.insert(metadata.tenant_token, Arc::clone(&context));
                            context
                        }
                    };
                    total_bytes = total_bytes.saturating_add(raw.len());
                    authenticated.push((index, record.candidate, raw, context, metadata));
                }
                let authenticate = |(index, candidate, raw, context, metadata): (
                    usize,
                    ExpiryCandidate,
                    Vec<u8>,
                    Arc<TenantCryptoContext>,
                    crate::format::EnvelopeMetadata,
                )| {
                    let plaintext = context.decrypt_owned(&candidate.record_id, raw)?;
                    drop(plaintext);
                    Ok::<_, Error>((
                        index,
                        metadata.expires_at_ms == Some(candidate.expires_at_ms)
                            && candidate.expires_at_ms <= now_ms,
                    ))
                };
                let flags = if authenticated.len() >= PARALLEL_BATCH_ITEMS
                    && total_bytes >= PARALLEL_BATCH_BYTES
                {
                    authenticated
                        .into_par_iter()
                        .map(authenticate)
                        .collect::<Result<Vec<_>, Error>>()?
                } else {
                    authenticated
                        .into_iter()
                        .map(authenticate)
                        .collect::<Result<Vec<_>, Error>>()?
                };
                for (index, delete_current) in flags {
                    cleanup
                        .get_mut(index)
                        .ok_or(Error::BackendState("purge candidate index is invalid"))?
                        .delete_current = delete_current;
                }
                Ok::<_, Error>(cleanup)
            })
            .await??;
            total += self.backend.cleanup_candidates(cleanup).await?;
        }
    }
}

fn encrypt_item(
    tenant: &TenantCryptoContext,
    item: SetItem,
    now_ms: i64,
    randomness: &[u8],
) -> Result<Mutation, Error> {
    let record_id = tenant.record_id(&item.key)?;
    if item.expires_at_ms.is_some_and(|expiry| expiry <= now_ms) {
        item.value.zeroize();
        return Ok(Mutation::DeleteAny { record_id });
    }
    let revision = randomness
        .get(..16)
        .ok_or(Error::BackendState("batch randomness is unavailable"))?
        .try_into()
        .map_err(|_| Error::BackendState("batch randomness is unavailable"))?;
    let value_nonce = randomness
        .get(16..40)
        .ok_or(Error::BackendState("batch randomness is unavailable"))?
        .try_into()
        .map_err(|_| Error::BackendState("batch randomness is unavailable"))?;
    let catalog_nonce = randomness
        .get(40..64)
        .ok_or(Error::BackendState("batch randomness is unavailable"))?
        .try_into()
        .map_err(|_| Error::BackendState("batch randomness is unavailable"))?;
    let envelope = tenant.encrypt_record_with_material(
        &record_id,
        item.value,
        item.kind,
        item.expires_at_ms,
        revision,
        value_nonce,
    )?;
    let key_envelope = tenant.encrypt_record_with_material(
        &record_id,
        PlaintextBuffer::from_value(item.key.into_bytes()),
        ValueKind::CatalogKey,
        item.expires_at_ms,
        revision,
        catalog_nonce,
    )?;
    let tenant_token = *tenant.tenant_token();
    Ok(Mutation::Put {
        record_id,
        envelope,
        tenant_token,
        key_envelope,
    })
}

async fn expiry_worker(weak: Weak<Service>, mut stop: oneshot::Receiver<()>, interval: Duration) {
    if let Some(service) = weak.upgrade()
        && service.purge_expired().await.is_err()
        && service.is_closed()
    {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = &mut stop => return,
            _ = ticker.tick() => {
                let Some(service) = weak.upgrade() else {
                    return;
                };
                if service.purge_expired().await.is_err() && service.is_closed() {
                    return;
                }
            }
        }
    }
}

fn decode_entry(
    tenant: Arc<TenantCryptoContext>,
    record_id: RecordId,
    raw: Option<Vec<u8>>,
    expected_kind: Option<ValueKind>,
    now_ms: i64,
) -> Result<(Option<DecodedEntry>, Option<ExpiryCandidate>), Error> {
    let Some(raw) = raw else {
        return Ok((None, None));
    };
    let decrypted = tenant.decrypt_owned(&record_id, raw)?;
    let metadata = decrypted.metadata;
    if metadata.kind == ValueKind::CatalogKey {
        return Err(Error::Integrity);
    }
    if metadata
        .expires_at_ms
        .is_some_and(|expiry| expiry <= now_ms)
    {
        return Ok((None, Some(expiry_candidate(record_id, &metadata)?)));
    }
    if expected_kind.is_some_and(|kind| kind != metadata.kind) {
        return Err(Error::TypeMismatch);
    }
    let buffer = decrypted.into_buffer();
    Ok((
        Some(DecodedEntry {
            entry: Entry {
                value: buffer,
                value_offset: crate::format::RECORD_PREFIX_SIZE,
                expires_at_ms: metadata.expires_at_ms,
            },
            revision: metadata.revision,
        }),
        None,
    ))
}

fn authenticate_entry(
    tenant: Arc<TenantCryptoContext>,
    record_id: RecordId,
    raw: Option<Vec<u8>>,
    now_ms: i64,
) -> Result<(Option<EntryMetadata>, Option<ExpiryCandidate>), Error> {
    let Some(raw) = raw else {
        return Ok((None, None));
    };
    let decrypted = tenant.decrypt_owned(&record_id, raw)?;
    let metadata = decrypted.metadata;
    drop(decrypted);
    if metadata.kind == ValueKind::CatalogKey {
        return Err(Error::Integrity);
    }
    if metadata
        .expires_at_ms
        .is_some_and(|expiry| expiry <= now_ms)
    {
        return Ok((None, Some(expiry_candidate(record_id, &metadata)?)));
    }
    Ok((
        Some(EntryMetadata {
            kind: metadata.kind,
            encoded_size: metadata.plaintext_len,
            expires_at_ms: metadata.expires_at_ms,
        }),
        None,
    ))
}

fn expiry_candidate(
    record_id: RecordId,
    metadata: &crate::format::EnvelopeMetadata,
) -> Result<ExpiryCandidate, Error> {
    let expires_at_ms = metadata.expires_at_ms.ok_or(Error::Integrity)?;
    Ok(ExpiryCandidate {
        index_key: expiry_index_key(expires_at_ms, &record_id, &metadata.revision),
        expires_at_ms,
        record_id,
        revision: metadata.revision,
    })
}

fn decode_entries(
    tenant: Arc<TenantCryptoContext>,
    record_ids: Vec<RecordId>,
    raw: Vec<Option<Vec<u8>>>,
    expected_kind: Option<ValueKind>,
    now_ms: i64,
) -> Result<(Vec<Option<DecodedEntry>>, Vec<ExpiryCandidate>), Error> {
    if record_ids.len() != raw.len() {
        return Err(Error::BackendState(
            "backend returned an invalid batch length",
        ));
    }
    let item_count = raw.len();
    let total_bytes = raw.iter().flatten().map(Vec::len).sum::<usize>();
    let values = if item_count >= PARALLEL_BATCH_ITEMS && total_bytes >= PARALLEL_BATCH_BYTES {
        record_ids
            .into_par_iter()
            .zip(raw.into_par_iter())
            .map(|(record_id, raw)| {
                decode_entry(Arc::clone(&tenant), record_id, raw, expected_kind, now_ms)
            })
            .collect::<Result<Vec<_>, Error>>()?
    } else {
        record_ids
            .into_iter()
            .zip(raw)
            .map(|(record_id, raw)| {
                decode_entry(Arc::clone(&tenant), record_id, raw, expected_kind, now_ms)
            })
            .collect::<Result<Vec<_>, Error>>()?
    };
    let mut decoded = Vec::with_capacity(item_count);
    let mut expired = Vec::new();
    for (value, candidate) in values {
        decoded.push(value);
        if let Some(candidate) = candidate {
            expired.push(candidate);
        }
    }
    Ok((decoded, expired))
}

fn decode_catalog(
    tenant: Arc<TenantCryptoContext>,
    entries: Vec<CatalogEntry>,
    now_ms: i64,
) -> Result<(Vec<String>, Vec<ExpiryCandidate>), Error> {
    let mut keys = Vec::with_capacity(entries.len());
    let mut expired = Vec::new();
    for entry in entries {
        let decrypted = tenant.decrypt_owned(&entry.record_id, entry.key_envelope)?;
        let metadata = decrypted.metadata;
        if metadata.kind != ValueKind::CatalogKey {
            return Err(Error::Integrity);
        }
        let key = match String::from_utf8(decrypted.plaintext().to_vec()) {
            Ok(key) => key,
            Err(error) => {
                let mut plaintext = error.into_bytes();
                plaintext.zeroize();
                return Err(Error::Integrity);
            }
        };
        validate_identifier(&key)?;
        if tenant.record_id(&key)? != entry.record_id {
            return Err(Error::Integrity);
        }
        if let Some(expires_at_ms) = metadata.expires_at_ms
            && expires_at_ms <= now_ms
        {
            expired.push(ExpiryCandidate {
                index_key: expiry_index_key(expires_at_ms, &entry.record_id, &metadata.revision),
                expires_at_ms,
                record_id: entry.record_id,
                revision: metadata.revision,
            });
        } else {
            keys.push(key);
        }
    }
    Ok((keys, expired))
}

fn ensure_unique<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), Error> {
    let mut unique = HashSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(Error::Configuration("batch identifiers must be unique"));
        }
    }
    Ok(())
}

fn validate_batch_count(count: usize) -> Result<(), Error> {
    if count > MAX_BATCH_ITEMS {
        return Err(Error::Configuration("batch contains more than 10000 items"));
    }
    Ok(())
}

fn validate_set_batch(items: &[SetItem]) -> Result<(), Error> {
    validate_batch_count(items.len())?;
    let mut total_bytes = 0_usize;
    for item in items {
        total_bytes = total_bytes
            .checked_add(item.value.len())
            .ok_or(Error::Configuration("batch values are too large"))?;
    }
    validate_batch_value_bytes(total_bytes)
}

fn validate_batch_value_bytes(total_bytes: usize) -> Result<(), Error> {
    if total_bytes > MAX_BATCH_VALUE_BYTES {
        return Err(Error::Configuration(
            "batch values exceed the 64 MiB aggregate limit",
        ));
    }
    Ok(())
}

fn decode_catalog_cursor(
    cursor: Option<&str>,
    tenant: &TenantCryptoContext,
) -> Result<Option<RecordId>, Error> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let encoded = cursor
        .strip_prefix(CATALOG_CURSOR_PREFIX)
        .ok_or(Error::Configuration("key listing cursor is invalid"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Configuration("key listing cursor is invalid"))?;
    let payload: [u8; CATALOG_CURSOR_BYTES] = decoded
        .try_into()
        .map_err(|_| Error::Configuration("key listing cursor is invalid"))?;
    let record_id: RecordId = payload[..32]
        .try_into()
        .map_err(|_| Error::Configuration("key listing cursor is invalid"))?;
    let tag: [u8; 32] = payload[32..]
        .try_into()
        .map_err(|_| Error::Configuration("key listing cursor is invalid"))?;
    if !tenant.validates_catalog_cursor(&record_id, &tag) {
        return Err(Error::Configuration(
            "key listing cursor does not belong to this store and tenant",
        ));
    }
    Ok(Some(record_id))
}

fn encode_catalog_cursor(tenant: &TenantCryptoContext, record_id: &RecordId) -> String {
    let mut payload = [0_u8; CATALOG_CURSOR_BYTES];
    payload[..32].copy_from_slice(record_id);
    payload[32..].copy_from_slice(&tenant.catalog_cursor_tag(record_id));
    format!(
        "{CATALOG_CURSOR_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
    )
}

fn validate_identifier(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Configuration("identifiers cannot be empty"));
    }
    if value.len() > IDENTIFIER_LIMIT {
        return Err(Error::Configuration("identifier is too long"));
    }
    Ok(())
}

fn validate_expiry(value: Option<i64>) -> Result<(), Error> {
    if value.is_some_and(|value| value < 0) {
        return Err(Error::Configuration(
            "expiry cannot be before the Unix epoch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Duration;

    use tempfile::tempdir;

    use super::{
        Clock, MAX_BATCH_ITEMS, MAX_BATCH_VALUE_BYTES, Service, SetItem, StorageEngine,
        validate_batch_count, validate_batch_value_bytes,
    };
    use crate::crypto::{MasterKey, SystemRandom};
    use crate::error::Error;
    use crate::format::{PlaintextBuffer, ValueKind};

    #[test]
    fn batch_limits_are_enforced_before_service_work() {
        assert!(validate_batch_count(MAX_BATCH_ITEMS).is_ok());
        assert!(validate_batch_count(MAX_BATCH_ITEMS + 1).is_err());
        assert!(validate_batch_value_bytes(MAX_BATCH_VALUE_BYTES).is_ok());
        assert!(validate_batch_value_bytes(MAX_BATCH_VALUE_BYTES + 1).is_err());
    }

    #[tokio::test]
    async fn service_reopens_and_isolates_tenants() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("store");
        let key = MasterKey::generate().expect("key");
        let exported = key.copy();
        let service = Service::open(path.clone(), key, Duration::ZERO, StorageEngine::Sqlite)
            .await
            .expect("open");
        let first = service.tenant("first").expect("first tenant");
        let second = service.tenant("second").expect("second tenant");
        service
            .set_many(
                first,
                vec![SetItem {
                    key: "key".to_owned(),
                    value: PlaintextBuffer::from_value(b"secret".to_vec()),
                    kind: ValueKind::Bytes,
                    expires_at_ms: None,
                }],
            )
            .await
            .expect("set");
        assert!(
            service
                .get_many(second, vec!["key".to_owned()], Some(ValueKind::Bytes))
                .await
                .expect("read")
                .1
                .into_iter()
                .next()
                .expect("result")
                .is_none()
        );
        service.close().await.expect("close");

        let reopened = Service::open(path, exported, Duration::ZERO, StorageEngine::Sqlite)
            .await
            .expect("reopen");
        let first = reopened.tenant("first").expect("first tenant");
        let value = reopened
            .get_many(first, vec!["key".to_owned()], Some(ValueKind::Bytes))
            .await
            .expect("read")
            .1
            .into_iter()
            .next()
            .flatten()
            .expect("value");
        assert_eq!(value.value(), b"secret");
        reopened.close().await.expect("close");
    }

    struct FixedClock(AtomicI64);

    impl FixedClock {
        fn set(&self, value: i64) {
            self.0.store(value, Ordering::Release);
        }
    }

    impl Clock for FixedClock {
        fn now_ms(&self) -> Result<i64, Error> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    #[tokio::test]
    async fn expiry_boundary_uses_injected_clock() {
        let directory = tempdir().expect("tempdir");
        let clock = Arc::new(FixedClock(AtomicI64::new(999)));
        let service = Service::open_with_boundaries(
            directory.path().join("store"),
            MasterKey::generate().expect("key"),
            Duration::ZERO,
            StorageEngine::Sqlite,
            clock.clone(),
            Arc::new(SystemRandom),
        )
        .await
        .expect("open");
        let tenant = service.tenant("tenant").expect("tenant");
        service
            .set_many(
                Arc::clone(&tenant),
                vec![SetItem {
                    key: "key".to_owned(),
                    value: PlaintextBuffer::from_value(b"secret".to_vec()),
                    kind: ValueKind::Bytes,
                    expires_at_ms: Some(1_000),
                }],
            )
            .await
            .expect("set");
        assert!(
            service
                .get_many(Arc::clone(&tenant), vec!["key".to_owned()], None)
                .await
                .expect("read before expiry")
                .1
                .into_iter()
                .next()
                .flatten()
                .is_some()
        );

        clock.set(1_000);
        assert!(
            service
                .get_many(tenant, vec!["key".to_owned()], None)
                .await
                .expect("read at expiry")
                .1
                .into_iter()
                .next()
                .flatten()
                .is_none()
        );
        service.close().await.expect("close");
    }
}
