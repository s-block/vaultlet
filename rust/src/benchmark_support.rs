//! Production-path adapters used only by Criterion benchmarks.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{KeySchedule, MasterKey, SystemRandom, TenantCryptoContext};
use crate::format::{EnvelopeRef, PlaintextBuffer, RECORD_PREFIX_SIZE, ValueKind};
use crate::json::JsonDocument;
use crate::service::{Service, SetItem, StorageEngine};
use zeroize::Zeroizing;

pub struct ParsedJson {
    _document: JsonDocument,
}

pub struct JsonHarness;

impl JsonHarness {
    pub fn flat_object(entries: usize) -> Vec<u8> {
        let mut encoded = vec![crate::format::JSON_CODEC_VERSION];
        rmp::encode::write_map_len(
            &mut encoded,
            u32::try_from(entries).expect("benchmark JSON entry count"),
        )
        .expect("benchmark JSON map");
        for index in 0..entries {
            rmp::encode::write_str(&mut encoded, &format!("field-{index}"))
                .expect("benchmark JSON key");
            rmp::encode::write_uint(
                &mut encoded,
                u64::try_from(index).expect("benchmark JSON value"),
            )
            .expect("benchmark JSON value");
        }
        encoded
    }

    pub fn parse(encoded: Vec<u8>) -> ParsedJson {
        ParsedJson {
            _document: JsonDocument::from_entry(crate::service::Entry::from_buffer(
                Zeroizing::new(encoded),
                0,
            ))
            .expect("benchmark JSON document"),
        }
    }
}

pub struct CryptoHarness {
    tenant: Arc<TenantCryptoContext>,
    record_id: [u8; 32],
}

impl CryptoHarness {
    pub fn new() -> Self {
        let master = MasterKey::generate().expect("benchmark master key");
        let (_, schedule, _) =
            KeySchedule::create_header(&master, &SystemRandom).expect("benchmark key schedule");
        let tenant = Arc::new(
            schedule
                .tenant_context("benchmark-tenant")
                .expect("benchmark tenant context"),
        );
        let record_id = tenant
            .record_id("benchmark-key")
            .expect("benchmark record id");
        Self { tenant, record_id }
    }

    pub fn encrypt(&self, value: Vec<u8>) -> Vec<u8> {
        self.encrypt_prepared(Self::prepare(value))
    }

    pub fn prepare(value: Vec<u8>) -> Vec<u8> {
        let mut prepared = vec![0; RECORD_PREFIX_SIZE];
        prepared.extend(value);
        prepared
    }

    pub fn encrypt_prepared(&self, value: Vec<u8>) -> Vec<u8> {
        self.tenant
            .encrypt_record(
                &self.record_id,
                PlaintextBuffer::with_record_prefix(value).expect("benchmark plaintext"),
                ValueKind::Bytes,
                None,
                &SystemRandom,
            )
            .expect("benchmark encryption")
    }

    pub fn decrypt(&self, envelope: Vec<u8>) -> Vec<u8> {
        self.tenant
            .decrypt_owned(&self.record_id, envelope)
            .expect("benchmark decryption")
            .plaintext()
            .to_vec()
    }

    pub fn inspect(envelope: &[u8]) -> u64 {
        EnvelopeRef::parse(envelope)
            .expect("benchmark envelope")
            .metadata()
            .plaintext_len
    }
}

impl Default for CryptoHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub enum BenchEngine {
    Redb,
    Sqlite,
}

pub struct StoreHarness {
    service: Arc<Service>,
    tenant: Arc<TenantCryptoContext>,
}

impl StoreHarness {
    pub fn prepare_value(value: Vec<u8>) -> Vec<u8> {
        CryptoHarness::prepare(value)
    }

    pub async fn open(path: PathBuf, engine: BenchEngine) -> Self {
        let engine = match engine {
            BenchEngine::Redb => StorageEngine::Redb,
            BenchEngine::Sqlite => StorageEngine::Sqlite,
        };
        let service = Service::open(
            path,
            MasterKey::generate().expect("benchmark master key"),
            Duration::ZERO,
            engine,
        )
        .await
        .expect("benchmark store");
        let tenant = service
            .tenant("benchmark-tenant")
            .expect("benchmark tenant");
        Self { service, tenant }
    }

    pub async fn set(&self, key: String, value: Vec<u8>) {
        self.service
            .set(
                Arc::clone(&self.tenant),
                SetItem {
                    key,
                    value: PlaintextBuffer::with_record_prefix(value).expect("benchmark plaintext"),
                    kind: ValueKind::Bytes,
                    expires_at_ms: None,
                },
            )
            .await
            .expect("benchmark set");
    }

    pub async fn set_many(&self, values: Vec<(String, Vec<u8>)>) {
        self.service
            .set_many(
                Arc::clone(&self.tenant),
                values
                    .into_iter()
                    .map(|(key, value)| SetItem {
                        key,
                        value: PlaintextBuffer::with_record_prefix(value)
                            .expect("benchmark plaintext"),
                        kind: ValueKind::Bytes,
                        expires_at_ms: None,
                    })
                    .collect(),
            )
            .await
            .expect("benchmark set many");
    }

    pub async fn get(&self, key: String) -> Vec<u8> {
        let entry = self
            .service
            .get(Arc::clone(&self.tenant), key, ValueKind::Bytes)
            .await
            .expect("benchmark get")
            .expect("benchmark value");
        entry.value().to_vec()
    }

    pub async fn close(&self) {
        self.service.close().await.expect("benchmark close");
    }
}
