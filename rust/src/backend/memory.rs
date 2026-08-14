use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::{
    Backend, CatalogEntry, CatalogPage, CleanupCandidate, ExpiryCandidate, Mutation, RecordId,
    TenantToken, decode_put_envelopes,
};
use crate::error::Error;
use crate::format::{EnvelopeRef, decode_expiry_index_key, expiry_index_key};

#[derive(Clone, Default)]
struct State {
    header: Option<Vec<u8>>,
    records: BTreeMap<RecordId, Vec<u8>>,
    catalog: BTreeMap<(TenantToken, RecordId), Vec<u8>>,
    expiry: BTreeMap<[u8; 56], ()>,
    closed: bool,
}

pub(crate) struct MemoryBackend {
    state: Mutex<State>,
}

impl MemoryBackend {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
        })
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, Error> {
        self.state
            .lock()
            .map_err(|_| Error::BackendState("backend state is unavailable"))
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn load_or_initialize_header(&self, header: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut state = self.state()?;
        if let Some(current) = &state.header {
            return Ok(current.clone());
        }
        state.header = Some(header.clone());
        Ok(header)
    }

    async fn replace_header(&self, expected: Vec<u8>, replacement: Vec<u8>) -> Result<bool, Error> {
        let mut state = self.state()?;
        if state.header.as_ref() != Some(&expected) {
            return Ok(false);
        }
        state.header = Some(replacement);
        Ok(true)
    }

    async fn read_many(&self, record_ids: Vec<RecordId>) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let state = self.state()?;
        if state.closed {
            return Err(Error::Closed);
        }
        Ok(record_ids
            .iter()
            .map(|record_id| state.records.get(record_id).cloned())
            .collect())
    }

    async fn read_one(&self, record_id: RecordId) -> Result<Option<Vec<u8>>, Error> {
        let state = self.state()?;
        if state.closed {
            return Err(Error::Closed);
        }
        Ok(state.records.get(&record_id).cloned())
    }

    async fn list_catalog(
        &self,
        tenant_token: TenantToken,
        after: Option<RecordId>,
        limit: usize,
    ) -> Result<CatalogPage, Error> {
        let state = self.state()?;
        if state.closed {
            return Err(Error::Closed);
        }
        let start = (tenant_token, after.unwrap_or([0; 32]));
        let start_bound = if after.is_some() {
            Excluded(start)
        } else {
            Included(start)
        };
        let entries = state
            .catalog
            .range((start_bound, Included((tenant_token, [u8::MAX; 32]))))
            .take(CatalogPage::fetch_limit(limit)?)
            .map(|((_, record_id), key_envelope)| {
                if !state.records.contains_key(record_id) {
                    return Err(Error::Integrity);
                }
                Ok(CatalogEntry {
                    record_id: *record_id,
                    key_envelope: key_envelope.clone(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        CatalogPage::from_lookahead(entries, limit)
    }

    async fn mutate(&self, mutations: Vec<Mutation>) -> Result<Vec<bool>, Error> {
        let mut state = self.state()?;
        if state.closed {
            return Err(Error::Closed);
        }
        let mut staged = state.clone();
        let count = mutations.len();
        let mut results = Vec::with_capacity(count);
        for mutation in mutations {
            match mutation {
                Mutation::Put {
                    record_id,
                    envelope,
                    tenant_token,
                    key_envelope,
                } => {
                    remove_expiry(&mut staged, &record_id)?;
                    let decoded = decode_put_envelopes(&envelope, &key_envelope, &tenant_token)?;
                    staged.records.insert(record_id, envelope);
                    staged
                        .catalog
                        .insert((tenant_token, record_id), key_envelope);
                    if let Some(expiry) = decoded.expires_at_ms {
                        staged
                            .expiry
                            .insert(expiry_index_key(expiry, &record_id, &decoded.revision), ());
                    }
                    results.push(true);
                }
                Mutation::DeleteGuarded {
                    record_id,
                    revision,
                } => {
                    let matches = staged
                        .records
                        .get(&record_id)
                        .map(|value| EnvelopeRef::parse(value))
                        .transpose()?
                        .is_some_and(|envelope| envelope.revision() == &revision);
                    if !matches {
                        return Ok(vec![false; count]);
                    }
                    remove_expiry(&mut staged, &record_id)?;
                    staged.records.remove(&record_id);
                    staged
                        .catalog
                        .retain(|(_, candidate), _| candidate != &record_id);
                    results.push(true);
                }
                Mutation::DeleteAny { record_id } => {
                    let existed = staged.records.contains_key(&record_id);
                    remove_expiry(&mut staged, &record_id)?;
                    staged.records.remove(&record_id);
                    staged
                        .catalog
                        .retain(|(_, candidate), _| candidate != &record_id);
                    results.push(existed);
                }
            }
        }
        *state = staged;
        Ok(results)
    }

    async fn scan_due(&self, now_ms: i64, limit: usize) -> Result<Vec<ExpiryCandidate>, Error> {
        self.state()?
            .expiry
            .keys()
            .take(limit)
            .map(|key| {
                let (expires_at_ms, record_id, revision) = decode_expiry_index_key(key)?;
                Ok((expires_at_ms <= now_ms).then_some(ExpiryCandidate {
                    index_key: *key,
                    expires_at_ms,
                    record_id,
                    revision,
                }))
            })
            .take_while(|candidate| !matches!(candidate, Ok(None)))
            .filter_map(Result::transpose)
            .collect()
    }

    async fn cleanup_candidates(&self, candidates: Vec<CleanupCandidate>) -> Result<usize, Error> {
        let mut state = self.state()?;
        let mut deleted = 0;
        for cleanup in candidates {
            let candidate = cleanup.candidate;
            let matches = state
                .records
                .get(&candidate.record_id)
                .map(|value| EnvelopeRef::parse(value))
                .transpose()?
                .is_some_and(|envelope| envelope.revision() == &candidate.revision);
            if matches && cleanup.delete_current {
                state.records.remove(&candidate.record_id);
                state
                    .catalog
                    .retain(|(_, record_id), _| record_id != &candidate.record_id);
                deleted += 1;
            }
            state.expiry.remove(&candidate.index_key);
        }
        Ok(deleted)
    }

    async fn close(&self) -> Result<(), Error> {
        self.state()?.closed = true;
        Ok(())
    }
}

fn remove_expiry(state: &mut State, record_id: &RecordId) -> Result<(), Error> {
    let Some(envelope) = state
        .records
        .get(record_id)
        .map(|value| EnvelopeRef::parse(value))
        .transpose()?
    else {
        return Ok(());
    };
    if let Some(expiry) = envelope.expires_at_ms() {
        state
            .expiry
            .remove(&expiry_index_key(expiry, record_id, envelope.revision()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::MemoryBackend;
    use crate::backend::tests::backend_contract;

    #[tokio::test]
    async fn memory_backend_obeys_contract() {
        backend_contract(MemoryBackend::new()).await;
    }
}
