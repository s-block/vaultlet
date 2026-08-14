use async_trait::async_trait;

use crate::error::Error;
use crate::format::{EnvelopeMetadata, EnvelopeRef, ValueKind};

mod redb;
mod redis;
mod sqlite;

#[cfg(test)]
mod memory;

pub(crate) use redb::RedbBackend;
pub(crate) use redis::{RedisBackend, RedisConfig};
pub(crate) use sqlite::SqliteBackend;

pub(crate) type RecordId = [u8; 32];
pub(crate) type TenantToken = [u8; 32];

#[derive(Clone)]
pub(crate) struct ExpiryCandidate {
    pub(crate) index_key: [u8; 56],
    pub(crate) expires_at_ms: i64,
    pub(crate) record_id: RecordId,
    pub(crate) revision: [u8; 16],
}

pub(crate) struct CleanupCandidate {
    pub(crate) candidate: ExpiryCandidate,
    pub(crate) delete_current: bool,
}

pub(crate) struct ExpiryRecord {
    pub(crate) candidate: ExpiryCandidate,
    pub(crate) envelope: Option<Vec<u8>>,
}

pub(crate) struct CatalogEntry {
    pub(crate) record_id: RecordId,
    pub(crate) key_envelope: Vec<u8>,
}

pub(crate) struct CatalogPage {
    pub(crate) entries: Vec<CatalogEntry>,
    pub(crate) has_more: bool,
}

impl CatalogPage {
    pub(crate) fn fetch_limit(limit: usize) -> Result<usize, Error> {
        limit
            .checked_add(1)
            .ok_or(Error::BackendState("catalogue limit is invalid"))
    }

    pub(crate) fn from_lookahead(
        mut entries: Vec<CatalogEntry>,
        limit: usize,
    ) -> Result<Self, Error> {
        if entries.len() > Self::fetch_limit(limit)? {
            return Err(Error::BackendState(
                "backend returned too many catalogue entries",
            ));
        }
        let has_more = entries.len() > limit;
        entries.truncate(limit);
        Ok(Self { entries, has_more })
    }
}

pub(crate) enum Mutation {
    Put {
        record_id: RecordId,
        envelope: Vec<u8>,
        tenant_token: TenantToken,
        key_envelope: Vec<u8>,
    },
    DeleteGuarded {
        record_id: RecordId,
        revision: [u8; 16],
    },
    DeleteAny {
        record_id: RecordId,
    },
}

fn decode_put_envelopes(
    envelope: &[u8],
    key_envelope: &[u8],
    tenant_token: &TenantToken,
) -> Result<EnvelopeMetadata, Error> {
    let value = EnvelopeRef::parse(envelope)?.metadata();
    let key = EnvelopeRef::parse(key_envelope)?.metadata();
    if value.kind == ValueKind::CatalogKey
        || key.kind != ValueKind::CatalogKey
        || value.tenant_token != *tenant_token
        || key.tenant_token != *tenant_token
        || value.revision != key.revision
        || value.expires_at_ms != key.expires_at_ms
    {
        return Err(Error::Integrity);
    }
    Ok(value)
}

/// Persistent storage for opaque record identifiers and encrypted envelopes.
///
/// Implementations must make each mutation batch atomic, return snapshot-consistent
/// multi-reads and tenant catalogue reads, keep catalogue rows consistent with record
/// mutations, and compare guarded revisions in the transaction that removes a record.
#[async_trait]
pub(crate) trait Backend: Send + Sync {
    async fn load_or_initialize_header(&self, candidate: Vec<u8>) -> Result<Vec<u8>, Error>;
    async fn replace_header(&self, expected: Vec<u8>, replacement: Vec<u8>) -> Result<bool, Error>;
    async fn read_many(&self, record_ids: Vec<RecordId>) -> Result<Vec<Option<Vec<u8>>>, Error>;

    async fn read_one(&self, record_id: RecordId) -> Result<Option<Vec<u8>>, Error> {
        self.read_many(vec![record_id])
            .await?
            .pop()
            .ok_or(Error::BackendState(
                "backend returned an invalid batch length",
            ))
    }
    async fn list_catalog(
        &self,
        tenant_token: TenantToken,
        after: Option<RecordId>,
        limit: usize,
    ) -> Result<CatalogPage, Error>;
    async fn mutate(&self, mutations: Vec<Mutation>) -> Result<Vec<bool>, Error>;

    async fn mutate_one(&self, mutation: Mutation) -> Result<bool, Error> {
        self.mutate(vec![mutation])
            .await?
            .into_iter()
            .next()
            .ok_or(Error::BackendState(
                "backend returned an invalid mutation length",
            ))
    }
    async fn scan_due(&self, now_ms: i64, limit: usize) -> Result<Vec<ExpiryCandidate>, Error>;

    async fn scan_due_records(
        &self,
        now_ms: i64,
        record_limit: usize,
        byte_limit: usize,
    ) -> Result<Vec<ExpiryRecord>, Error> {
        let candidates = self.scan_due(now_ms, record_limit).await?;
        let values = self
            .read_many(
                candidates
                    .iter()
                    .map(|candidate| candidate.record_id)
                    .collect(),
            )
            .await?;
        let mut total_bytes = 0_usize;
        Ok(candidates
            .into_iter()
            .zip(values)
            .take_while(|(_, value)| {
                let next = value.as_ref().map_or(0, Vec::len);
                let include = total_bytes == 0 || total_bytes.saturating_add(next) <= byte_limit;
                if include {
                    total_bytes = total_bytes.saturating_add(next);
                }
                include
            })
            .map(|(candidate, envelope)| ExpiryRecord {
                candidate,
                envelope,
            })
            .collect())
    }
    async fn cleanup_candidates(&self, candidates: Vec<CleanupCandidate>) -> Result<usize, Error>;
    async fn close(&self) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Backend, CleanupCandidate, Mutation};
    use crate::format::{Envelope, ValueKind};

    fn envelope(revision: [u8; 16], expiry: Option<i64>) -> Vec<u8> {
        Envelope {
            kind: ValueKind::Bytes,
            expires_at_ms: expiry,
            plaintext_len: 1,
            revision,
            tenant_token: [8; 32],
            nonce: [2; 24],
            ciphertext: vec![3; 17],
        }
        .encode()
        .expect("envelope")
    }

    fn catalog_envelope(revision: [u8; 16], expiry: Option<i64>) -> Vec<u8> {
        Envelope {
            kind: ValueKind::CatalogKey,
            expires_at_ms: expiry,
            plaintext_len: 1,
            revision,
            tenant_token: [8; 32],
            nonce: [2; 24],
            ciphertext: vec![3; 17],
        }
        .encode()
        .expect("catalog envelope")
    }

    pub(super) async fn backend_contract(backend: Arc<dyn Backend>) {
        assert_eq!(
            backend
                .load_or_initialize_header(vec![1, 2, 3])
                .await
                .expect("initialize"),
            vec![1, 2, 3]
        );
        assert_eq!(
            backend
                .load_or_initialize_header(vec![9, 9, 9])
                .await
                .expect("load existing"),
            vec![1, 2, 3]
        );
        assert!(
            backend
                .replace_header(vec![1, 2, 3], vec![3, 2, 1])
                .await
                .expect("replace header")
        );
        assert!(
            !backend
                .replace_header(vec![1, 2, 3], vec![9, 9, 9])
                .await
                .expect("compare header")
        );
        assert_eq!(
            backend
                .load_or_initialize_header(vec![8, 8, 8])
                .await
                .expect("header"),
            vec![3, 2, 1]
        );
        let first = [4; 32];
        let second = [5; 32];
        backend
            .mutate(vec![
                Mutation::Put {
                    record_id: first,
                    envelope: envelope([6; 16], Some(10)),
                    tenant_token: [8; 32],
                    key_envelope: catalog_envelope([6; 16], Some(10)),
                },
                Mutation::Put {
                    record_id: second,
                    envelope: envelope([7; 16], None),
                    tenant_token: [8; 32],
                    key_envelope: catalog_envelope([7; 16], None),
                },
            ])
            .await
            .expect("write");
        let values = backend.read_many(vec![second, first]).await.expect("read");
        assert!(values.iter().all(Option::is_some));
        let first_page = backend
            .list_catalog([8; 32], None, 1)
            .await
            .expect("bounded catalog");
        assert_eq!(first_page.entries.len(), 1);
        assert!(first_page.has_more);
        let second_page = backend
            .list_catalog([8; 32], Some(first_page.entries[0].record_id), 1)
            .await
            .expect("continued catalog");
        assert_eq!(second_page.entries.len(), 1);
        assert_eq!(second_page.entries[0].record_id, second);
        assert!(!second_page.has_more);
        assert_eq!(backend.scan_due(10, 10).await.expect("expiry").len(), 1);

        let results = backend
            .mutate(vec![
                Mutation::DeleteGuarded {
                    record_id: first,
                    revision: [0; 16],
                },
                Mutation::DeleteGuarded {
                    record_id: second,
                    revision: [7; 16],
                },
            ])
            .await
            .expect("guarded delete");
        assert_eq!(results, [false, false]);
        assert!(
            backend
                .read_many(vec![first, second])
                .await
                .expect("read")
                .iter()
                .all(Option::is_some)
        );

        backend
            .mutate(vec![Mutation::Put {
                record_id: first,
                envelope: envelope([9; 16], None),
                tenant_token: [8; 32],
                key_envelope: catalog_envelope([9; 16], None),
            }])
            .await
            .expect("overwrite");
        assert!(backend.scan_due(10, 10).await.expect("expiry").is_empty());

        backend
            .mutate(vec![Mutation::Put {
                record_id: first,
                envelope: envelope([10; 16], Some(20)),
                tenant_token: [8; 32],
                key_envelope: catalog_envelope([10; 16], Some(20)),
            }])
            .await
            .expect("expiring write");
        let stale_candidate = backend
            .scan_due(20, 10)
            .await
            .expect("expiry")
            .into_iter()
            .next()
            .expect("candidate");
        backend
            .mutate(vec![Mutation::Put {
                record_id: first,
                envelope: envelope([11; 16], None),
                tenant_token: [8; 32],
                key_envelope: catalog_envelope([11; 16], None),
            }])
            .await
            .expect("rewrite");
        assert_eq!(
            backend
                .cleanup_candidates(vec![CleanupCandidate {
                    candidate: stale_candidate,
                    delete_current: true,
                }])
                .await
                .expect("stale cleanup"),
            0
        );
        assert!(
            backend
                .read_many(vec![first])
                .await
                .expect("read rewritten value")[0]
                .is_some()
        );

        backend
            .mutate(vec![Mutation::Put {
                record_id: first,
                envelope: envelope([12; 16], Some(30)),
                tenant_token: [8; 32],
                key_envelope: catalog_envelope([12; 16], Some(30)),
            }])
            .await
            .expect("expiring write");
        let current_candidate = backend
            .scan_due(30, 10)
            .await
            .expect("expiry")
            .into_iter()
            .next()
            .expect("candidate");
        assert_eq!(
            backend
                .cleanup_candidates(vec![CleanupCandidate {
                    candidate: current_candidate,
                    delete_current: true,
                }])
                .await
                .expect("current cleanup"),
            1
        );
        assert!(
            backend
                .read_many(vec![first])
                .await
                .expect("read cleaned value")[0]
                .is_none()
        );
        let catalog = backend
            .list_catalog([8; 32], None, 2)
            .await
            .expect("catalog");
        assert_eq!(catalog.entries.len(), 1);
        assert!(!catalog.has_more);
        assert_eq!(catalog.entries[0].record_id, second);
    }
}
