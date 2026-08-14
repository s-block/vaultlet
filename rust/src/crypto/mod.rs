use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
#[cfg(test)]
use crate::format::Envelope;
use crate::format::{
    EnvelopeMetadata, EnvelopeRef, Header, MAX_VALUE_SIZE, PlaintextBuffer, RECORD_PREFIX_SIZE,
    ValueKind, encode_record_prefix, record_aad,
};

const MASTER_KEY_SIZE: usize = 32;
const HEADER_INFO: &[u8] = b"vaultlet-header-key-v1";
const LOOKUP_INFO: &[u8] = b"vaultlet-lookup-key-v1";
const TENANT_ROOT_INFO: &[u8] = b"vaultlet-tenant-root-v1";
const WRAPPING_INFO: &[u8] = b"vaultlet-master-wrap-key-v1";

pub(crate) trait RandomSource: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error>;
}

pub(crate) struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(destination).map_err(Error::backend)
    }
}

pub(crate) struct MasterKey(Zeroizing<[u8; MASTER_KEY_SIZE]>);

impl MasterKey {
    pub(crate) fn generate() -> Result<Self, Error> {
        Self::generate_with(&SystemRandom)
    }

    fn generate_with(random: &dyn RandomSource) -> Result<Self, Error> {
        let mut key = Zeroizing::new([0_u8; MASTER_KEY_SIZE]);
        random.fill(key.as_mut())?;
        Ok(Self(key))
    }

    pub(crate) fn from_slice(value: &[u8]) -> Result<Self, Error> {
        let key: [u8; MASTER_KEY_SIZE] = value
            .try_into()
            .map_err(|_| Error::Configuration("master keys must contain exactly 32 bytes"))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub(crate) fn from_base64(value: &str) -> Result<Self, Error> {
        let mut decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| Error::Configuration("master key is not valid base64"))?;
        let result = Self::from_slice(&decoded);
        decoded.zeroize();
        result
    }

    pub(crate) fn expose(&self) -> &[u8; MASTER_KEY_SIZE] {
        &self.0
    }

    pub(crate) fn copy(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }

    pub(crate) fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0.as_slice())
    }
}

pub(crate) struct KeySchedule {
    store_id: [u8; 16],
    header_key: Zeroizing<[u8; 32]>,
    lookup_key: Zeroizing<[u8; 32]>,
    tenant_root: Zeroizing<[u8; 32]>,
}

/// Tenant-scoped derivations retained by a native tenant handle.
pub(crate) struct TenantCryptoContext {
    store_id: [u8; 16],
    record_mac: Hmac<Sha256>,
    tenant_token: [u8; 32],
    cipher: XChaCha20Poly1305,
}

pub(crate) struct DecryptedEnvelope {
    buffer: Zeroizing<Vec<u8>>,
    pub(crate) metadata: EnvelopeMetadata,
}

impl DecryptedEnvelope {
    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.buffer[RECORD_PREFIX_SIZE..]
    }

    pub(crate) fn into_buffer(self) -> Zeroizing<Vec<u8>> {
        self.buffer
    }
}

impl KeySchedule {
    pub(crate) fn new(
        master: &MasterKey,
        salt: &[u8; 32],
        store_id: [u8; 16],
    ) -> Result<Self, Error> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), master.expose());
        let mut header_key = Zeroizing::new([0_u8; 32]);
        let mut lookup_key = Zeroizing::new([0_u8; 32]);
        let mut tenant_root = Zeroizing::new([0_u8; 32]);
        hkdf.expand(HEADER_INFO, header_key.as_mut())
            .map_err(|_| Error::Configuration("key derivation failed"))?;
        hkdf.expand(LOOKUP_INFO, lookup_key.as_mut())
            .map_err(|_| Error::Configuration("key derivation failed"))?;
        hkdf.expand(TENANT_ROOT_INFO, tenant_root.as_mut())
            .map_err(|_| Error::Configuration("key derivation failed"))?;
        Ok(Self {
            store_id,
            header_key,
            lookup_key,
            tenant_root,
        })
    }

    pub(crate) fn create_header(
        master: &MasterKey,
        random: &dyn RandomSource,
    ) -> Result<(Header, Self, MasterKey), Error> {
        let mut store_id = [0_u8; 16];
        let mut data_salt = [0_u8; 32];
        random.fill(&mut store_id)?;
        random.fill(&mut data_salt)?;
        let data_key = MasterKey::generate_with(random)?;
        let schedule = Self::new(&data_key, &data_salt, store_id)?;
        let header = Self::wrap_header(master, &data_key, store_id, data_salt, random)?;
        Ok((header, schedule, data_key))
    }

    pub(crate) fn from_header(
        master: &MasterKey,
        header: &Header,
    ) -> Result<(Self, MasterKey), Error> {
        let data_key = match header {
            Header::Legacy { tag, .. } => {
                let schedule = Self::new(master, header.data_salt(), *header.store_id())?;
                let mut verifier = Hmac::<Sha256>::new_from_slice(schedule.header_key.as_slice())
                    .map_err(|_| Error::Configuration("key verification failed"))?;
                verifier.update(&header.authenticated_bytes());
                verifier.verify_slice(tag).map_err(|_| Error::InvalidKey)?;
                return Ok((schedule, master.copy()));
            }
            Header::Wrapped {
                wrapping_salt,
                nonce,
                wrapped_data_key,
                ..
            } => {
                let wrapping_key = derive_wrapping_key(master, wrapping_salt)?;
                let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice())
                    .map_err(|_| Error::Configuration("key wrapping initialization failed"))?;
                let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Integrity)?;
                let mut plaintext = cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: wrapped_data_key,
                            aad: &header.authenticated_bytes(),
                        },
                    )
                    .map_err(|_| Error::InvalidKey)?;
                let result = MasterKey::from_slice(&plaintext);
                plaintext.zeroize();
                result?
            }
        };
        let schedule = Self::new(&data_key, header.data_salt(), *header.store_id())?;
        Ok((schedule, data_key))
    }

    pub(crate) fn rotate_header(
        current: &Header,
        data_key: &MasterKey,
        new_master: &MasterKey,
        random: &dyn RandomSource,
    ) -> Result<Header, Error> {
        Self::wrap_header(
            new_master,
            data_key,
            *current.store_id(),
            *current.data_salt(),
            random,
        )
    }

    fn wrap_header(
        master: &MasterKey,
        data_key: &MasterKey,
        store_id: [u8; 16],
        data_salt: [u8; 32],
        random: &dyn RandomSource,
    ) -> Result<Header, Error> {
        let mut wrapping_salt = [0_u8; 32];
        let mut nonce = [0_u8; 24];
        random.fill(&mut wrapping_salt)?;
        random.fill(&mut nonce)?;
        let mut header = Header::Wrapped {
            store_id,
            data_salt,
            wrapping_salt,
            nonce,
            wrapped_data_key: [0; 48],
        };
        let wrapping_key = derive_wrapping_key(master, &wrapping_salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice())
            .map_err(|_| Error::Configuration("key wrapping initialization failed"))?;
        let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Integrity)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: data_key.expose(),
                    aad: &header.authenticated_bytes(),
                },
            )
            .map_err(|_| Error::Integrity)?;
        let wrapped_data_key = ciphertext.try_into().map_err(|_| Error::Integrity)?;
        if let Header::Wrapped {
            wrapped_data_key: destination,
            ..
        } = &mut header
        {
            *destination = wrapped_data_key;
        }
        Ok(header)
    }

    #[cfg(test)]
    pub(crate) fn record_id(&self, tenant: &str, key: &str) -> Result<[u8; 32], Error> {
        self.tenant_context(tenant)?.record_id(key)
    }

    pub(crate) fn tenant_context(&self, tenant: &str) -> Result<TenantCryptoContext, Error> {
        let tenant_token = self.tenant_token(tenant)?;
        self.tenant_context_from_token(tenant_token)
    }

    pub(crate) fn tenant_context_from_token(
        &self,
        tenant_token: [u8; 32],
    ) -> Result<TenantCryptoContext, Error> {
        let aead_key = self.tenant_key(&tenant_token)?;
        let cipher = XChaCha20Poly1305::new_from_slice(aead_key.as_slice())
            .map_err(|_| Error::Configuration("encryption initialization failed"))?;
        let mut record_mac = Hmac::<Sha256>::new_from_slice(self.lookup_key.as_slice())
            .map_err(|_| Error::Configuration("identifier derivation failed"))?;
        record_mac.update(b"vaultlet-record-id-v1\0");
        record_mac.update(&tenant_token);
        Ok(TenantCryptoContext {
            store_id: self.store_id,
            record_mac,
            tenant_token,
            cipher,
        })
    }

    pub(crate) fn tenant_token(&self, tenant: &str) -> Result<[u8; 32], Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.lookup_key.as_slice())
            .map_err(|_| Error::Configuration("identifier derivation failed"))?;
        mac.update(b"vaultlet-tenant-id-v1\0");
        mac.update(
            &u64::try_from(tenant.len())
                .map_err(|_| Error::Configuration("identifier is too long"))?
                .to_be_bytes(),
        );
        mac.update(tenant.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    fn tenant_key(&self, tenant_token: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let hkdf = Hkdf::<Sha256>::new(Some(tenant_token), self.tenant_root.as_slice());
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(b"vaultlet-tenant-aead-v1", key.as_mut())
            .map_err(|_| Error::Configuration("tenant key derivation failed"))?;
        Ok(key)
    }

    #[cfg(test)]
    pub(crate) fn encrypt(
        &self,
        tenant: &str,
        record_id: &[u8; 32],
        plaintext: Vec<u8>,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        random: &dyn RandomSource,
    ) -> Result<Envelope, Error> {
        self.tenant_context(tenant)?
            .encrypt(record_id, plaintext, kind, expires_at_ms, random)
    }

    #[cfg(test)]
    pub(crate) fn decrypt(
        &self,
        tenant: &str,
        record_id: &[u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<u8>, Error> {
        let encoded = envelope.encode()?;
        self.tenant_context(tenant)?
            .decrypt_owned(record_id, encoded)
            .map(|value| value.plaintext().to_vec())
    }
}

impl TenantCryptoContext {
    pub(crate) fn tenant_token(&self) -> &[u8; 32] {
        &self.tenant_token
    }

    pub(crate) fn record_id(&self, key: &str) -> Result<[u8; 32], Error> {
        let mut mac = self.record_mac.clone();
        mac.update(
            &u64::try_from(key.len())
                .map_err(|_| Error::Configuration("identifier is too long"))?
                .to_be_bytes(),
        );
        mac.update(key.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    pub(crate) fn catalog_cursor_tag(&self, record_id: &[u8; 32]) -> [u8; 32] {
        let mut mac = self.record_mac.clone();
        // Valid record identifiers prefix the key with a length of at most 1,024.
        // This impossible length marker separates cursor tags from that domain.
        mac.update(&u64::MAX.to_be_bytes());
        mac.update(b"vaultlet-catalog-cursor-v1\0");
        mac.update(record_id);
        mac.finalize().into_bytes().into()
    }

    pub(crate) fn validates_catalog_cursor(&self, record_id: &[u8; 32], tag: &[u8; 32]) -> bool {
        self.catalog_cursor_tag(record_id).ct_eq(tag).into()
    }

    #[cfg(test)]
    pub(crate) fn encrypt(
        &self,
        record_id: &[u8; 32],
        plaintext: Vec<u8>,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        random: &dyn RandomSource,
    ) -> Result<Envelope, Error> {
        let mut revision = [0_u8; 16];
        random.fill(&mut revision)?;
        self.encrypt_with_revision(record_id, plaintext, kind, expires_at_ms, revision, random)
    }

    pub(crate) fn encrypt_record(
        &self,
        record_id: &[u8; 32],
        plaintext: PlaintextBuffer,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        random: &dyn RandomSource,
    ) -> Result<Vec<u8>, Error> {
        let mut revision = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        random.fill(&mut revision)?;
        random.fill(&mut nonce)?;
        self.encrypt_record_with_material(
            record_id,
            plaintext,
            kind,
            expires_at_ms,
            revision,
            nonce,
        )
    }

    #[cfg(test)]
    fn encrypt_with_revision(
        &self,
        record_id: &[u8; 32],
        plaintext: Vec<u8>,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        revision: [u8; 16],
        random: &dyn RandomSource,
    ) -> Result<Envelope, Error> {
        let mut nonce = [0_u8; 24];
        random.fill(&mut nonce)?;
        self.encrypt_with_material(record_id, plaintext, kind, expires_at_ms, revision, nonce)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn encrypt_with_material(
        &self,
        record_id: &[u8; 32],
        mut plaintext: Vec<u8>,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        revision: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<Envelope, Error> {
        if plaintext.len() > MAX_VALUE_SIZE {
            plaintext.zeroize();
            return Err(Error::Configuration("value is too large"));
        }
        let plaintext_len = u64::try_from(plaintext.len())
            .map_err(|_| Error::Configuration("value is too large"))?;
        let metadata = EnvelopeMetadata {
            kind,
            expires_at_ms,
            plaintext_len,
            revision,
            tenant_token: self.tenant_token,
            nonce,
        };
        let aad = record_aad(&self.store_id, record_id, &metadata);
        let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Integrity)?;
        plaintext.reserve(16);
        if self
            .cipher
            .encrypt_in_place(&nonce_value, &aad, &mut plaintext)
            .is_err()
        {
            plaintext.zeroize();
            return Err(Error::Integrity);
        }
        Ok(Envelope {
            kind,
            expires_at_ms,
            plaintext_len,
            revision,
            tenant_token: self.tenant_token,
            nonce,
            ciphertext: plaintext,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encrypt_record_with_material(
        &self,
        record_id: &[u8; 32],
        plaintext: PlaintextBuffer,
        kind: ValueKind,
        expires_at_ms: Option<i64>,
        revision: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, Error> {
        let plaintext_len = plaintext.len();
        if plaintext_len > MAX_VALUE_SIZE {
            return Err(Error::Configuration("value is too large"));
        }
        let plaintext_len =
            u64::try_from(plaintext_len).map_err(|_| Error::Configuration("value is too large"))?;
        let metadata = EnvelopeMetadata {
            kind,
            expires_at_ms,
            plaintext_len,
            revision,
            tenant_token: self.tenant_token,
            nonce,
        };
        let aad = record_aad(&self.store_id, record_id, &metadata);
        let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Integrity)?;
        let mut record = plaintext.into_record_buffer()?;
        let record_buffer = record.buffer_mut();
        record_buffer
            .try_reserve(16)
            .map_err(|_| Error::Configuration("value is too large"))?;
        let tag = match self.cipher.encrypt_inout_detached(
            &nonce_value,
            &aad,
            (&mut record_buffer[RECORD_PREFIX_SIZE..]).into(),
        ) {
            Ok(tag) => tag,
            Err(_) => return Err(Error::Integrity),
        };
        record_buffer.extend_from_slice(&tag);
        let ciphertext_len = plaintext_len.checked_add(16).ok_or(Error::Integrity)?;
        encode_record_prefix(
            &mut record_buffer[..RECORD_PREFIX_SIZE],
            &metadata,
            ciphertext_len,
        );
        record.into_ciphertext()
    }

    pub(crate) fn decrypt_owned(
        &self,
        record_id: &[u8; 32],
        encoded: Vec<u8>,
    ) -> Result<DecryptedEnvelope, Error> {
        decrypt_owned(
            &self.store_id,
            &self.cipher,
            record_id,
            encoded,
            &self.tenant_token,
        )
    }
}

fn decrypt_owned(
    store_id: &[u8; 16],
    cipher: &XChaCha20Poly1305,
    record_id: &[u8; 32],
    mut encoded: Vec<u8>,
    expected_token: &[u8; 32],
) -> Result<DecryptedEnvelope, Error> {
    let envelope = EnvelopeRef::parse(&encoded)?;
    let metadata = envelope.metadata();
    let ciphertext_len = envelope.ciphertext.len();
    if !bool::from(expected_token.ct_eq(&metadata.tenant_token)) {
        encoded.zeroize();
        return Err(Error::Integrity);
    }
    let aad = record_aad(store_id, record_id, &metadata);
    let nonce = XNonce::try_from(metadata.nonce.as_slice()).map_err(|_| Error::Integrity)?;
    let tag_start = RECORD_PREFIX_SIZE + ciphertext_len.checked_sub(16).ok_or(Error::Integrity)?;
    let tag = Tag::try_from(&encoded[tag_start..]).map_err(|_| Error::Integrity)?;
    if cipher
        .decrypt_inout_detached(
            &nonce,
            &aad,
            (&mut encoded[RECORD_PREFIX_SIZE..tag_start]).into(),
            &tag,
        )
        .is_err()
    {
        encoded.zeroize();
        return Err(Error::Integrity);
    }
    let plaintext_end = RECORD_PREFIX_SIZE
        + usize::try_from(metadata.plaintext_len).map_err(|_| Error::Integrity)?;
    if tag_start != plaintext_end {
        encoded.zeroize();
        return Err(Error::Integrity);
    }
    encoded.truncate(plaintext_end);
    Ok(DecryptedEnvelope {
        buffer: Zeroizing::new(encoded),
        metadata,
    })
}

fn derive_wrapping_key(master: &MasterKey, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master.expose());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(WRAPPING_INFO, key.as_mut())
        .map_err(|_| Error::Configuration("key wrapping derivation failed"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::{KeySchedule, MasterKey, RandomSource, SystemRandom};
    use crate::error::Error;
    use crate::format::ValueKind;

    #[test]
    fn wrong_key_is_rejected_and_debug_is_not_derived() {
        let key = MasterKey::generate().expect("key");
        let wrong_key = MasterKey::generate().expect("key");
        let (header, _, _) = KeySchedule::create_header(&key, &SystemRandom).expect("header");
        assert!(KeySchedule::from_header(&wrong_key, &header).is_err());

        let mut modified = header;
        match &mut modified {
            crate::format::Header::Legacy { store_id, .. }
            | crate::format::Header::Wrapped { store_id, .. } => store_id[0] ^= 1,
        }
        assert!(KeySchedule::from_header(&key, &modified).is_err());
    }

    #[test]
    fn tenants_and_aad_are_separated() {
        let key = MasterKey::generate().expect("key");
        let (_, schedule, _) = KeySchedule::create_header(&key, &SystemRandom).expect("header");
        let first_id = schedule.record_id("first", "same").expect("id");
        let second_id = schedule.record_id("second", "same").expect("id");
        let other_key_id = schedule.record_id("first", "other").expect("id");
        assert_ne!(first_id, second_id);

        let envelope = schedule
            .encrypt(
                "first",
                &first_id,
                b"secret".to_vec(),
                ValueKind::Bytes,
                None,
                &SystemRandom,
            )
            .expect("encrypt");
        assert_eq!(
            schedule
                .decrypt("first", &first_id, &envelope)
                .expect("decrypt"),
            b"secret"
        );
        assert!(schedule.decrypt("second", &second_id, &envelope).is_err());
        assert!(schedule.decrypt("first", &other_key_id, &envelope).is_err());

        let mut modified = envelope;
        modified.expires_at_ms = Some(1);
        assert!(schedule.decrypt("first", &first_id, &modified).is_err());
    }

    struct DeterministicRandom(AtomicU8);

    impl RandomSource for DeterministicRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), Error> {
            let value = self.0.fetch_add(1, Ordering::Relaxed);
            destination.fill(value);
            Ok(())
        }
    }

    #[test]
    fn randomness_boundary_is_injectable() {
        let key = MasterKey::generate().expect("key");
        let random = DeterministicRandom(AtomicU8::new(1));
        let (header, schedule, _) = KeySchedule::create_header(&key, &random).expect("header");
        assert_eq!(*header.store_id(), [1; 16]);
        assert_eq!(*header.data_salt(), [2; 32]);

        let record_id = schedule.record_id("tenant", "key").expect("id");
        let envelope = schedule
            .encrypt(
                "tenant",
                &record_id,
                b"secret".to_vec(),
                ValueKind::Bytes,
                None,
                &random,
            )
            .expect("encrypt");
        assert_eq!(envelope.revision, [6; 16]);
        assert_eq!(envelope.nonce, [7; 24]);
    }

    #[test]
    fn stores_and_authenticated_fields_are_separated() {
        let key = MasterKey::generate().expect("key");
        let random = DeterministicRandom(AtomicU8::new(1));
        let (_, first_store, _) = KeySchedule::create_header(&key, &random).expect("header");
        let (_, second_store, _) = KeySchedule::create_header(&key, &random).expect("header");
        let first_id = first_store.record_id("tenant", "key").expect("id");
        let second_id = second_store.record_id("tenant", "key").expect("id");
        assert_ne!(first_id, second_id);

        let envelope = first_store
            .encrypt(
                "tenant",
                &first_id,
                b"secret".to_vec(),
                ValueKind::Bytes,
                Some(42),
                &random,
            )
            .expect("encrypt");
        assert!(
            second_store
                .decrypt("tenant", &second_id, &envelope)
                .is_err()
        );

        let mut changed_kind = envelope.clone();
        changed_kind.kind = ValueKind::Json;
        assert!(
            first_store
                .decrypt("tenant", &first_id, &changed_kind)
                .is_err()
        );
        let mut changed_revision = envelope.clone();
        changed_revision.revision[0] ^= 1;
        assert!(
            first_store
                .decrypt("tenant", &first_id, &changed_revision)
                .is_err()
        );
        let mut changed_nonce = envelope;
        changed_nonce.nonce[0] ^= 1;
        assert!(
            first_store
                .decrypt("tenant", &first_id, &changed_nonce)
                .is_err()
        );
    }

    #[test]
    fn rotating_master_key_preserves_data_schedule() {
        let current = MasterKey::generate().expect("key");
        let replacement = MasterKey::generate().expect("key");
        let (header, schedule, data_key) =
            KeySchedule::create_header(&current, &SystemRandom).expect("header");
        let record_id = schedule.record_id("tenant", "key").expect("id");
        let envelope = schedule
            .encrypt(
                "tenant",
                &record_id,
                b"secret".to_vec(),
                ValueKind::Bytes,
                None,
                &SystemRandom,
            )
            .expect("encrypt");

        let rotated = KeySchedule::rotate_header(&header, &data_key, &replacement, &SystemRandom)
            .expect("rotate");
        assert!(KeySchedule::from_header(&current, &rotated).is_err());
        let (reopened, _) =
            KeySchedule::from_header(&replacement, &rotated).expect("replacement key");
        assert_eq!(reopened.record_id("tenant", "key").expect("id"), record_id);
        assert_eq!(
            reopened
                .decrypt("tenant", &record_id, &envelope)
                .expect("decrypt"),
            b"secret"
        );
    }
}
