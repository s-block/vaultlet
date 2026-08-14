use crate::error::Error;
use zeroize::Zeroize;

pub(crate) const HEADER_VERSION: u16 = 2;
pub(crate) const RECORD_VERSION: u16 = 1;
pub(crate) const JSON_CODEC_VERSION: u8 = 1;
pub(crate) const MAX_VALUE_SIZE: usize = 64 * 1024 * 1024;

const HEADER_MAGIC: &[u8; 8] = b"VLTHDR\0\0";
const RECORD_MAGIC: &[u8; 8] = b"VLTREC\0\0";
const LEGACY_HEADER_VERSION: u16 = 1;
const LEGACY_HEADER_SIZE: usize = 8 + 2 + 16 + 32 + 32;
const WRAPPED_HEADER_SIZE: usize = 8 + 2 + 16 + 32 + 32 + 24 + 48;
pub(crate) const RECORD_PREFIX_SIZE: usize = 8 + 2 + 1 + 8 + 8 + 16 + 32 + 24 + 8;
const RECORD_AAD_DOMAIN: &[u8; 23] = b"vaultlet-record-aad-v1\0";
const RECORD_AAD_SIZE: usize = RECORD_AAD_DOMAIN.len() + 16 + 32 + 1 + 8 + 8 + 16 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ValueKind {
    Bytes = 1,
    Json = 2,
    CatalogKey = 3,
}

impl TryFrom<u8> for ValueKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bytes),
            2 => Ok(Self::Json),
            3 => Ok(Self::CatalogKey),
            _ => Err(Error::Integrity),
        }
    }
}

#[derive(Clone)]
pub(crate) enum Header {
    Legacy {
        store_id: [u8; 16],
        salt: [u8; 32],
        tag: [u8; 32],
    },
    Wrapped {
        store_id: [u8; 16],
        data_salt: [u8; 32],
        wrapping_salt: [u8; 32],
        nonce: [u8; 24],
        wrapped_data_key: [u8; 48],
    },
}

impl Header {
    pub(crate) fn store_id(&self) -> &[u8; 16] {
        match self {
            Self::Legacy { store_id, .. } | Self::Wrapped { store_id, .. } => store_id,
        }
    }

    pub(crate) fn data_salt(&self) -> &[u8; 32] {
        match self {
            Self::Legacy { salt, .. } => salt,
            Self::Wrapped { data_salt, .. } => data_salt,
        }
    }

    pub(crate) fn authenticated_bytes(&self) -> Vec<u8> {
        match self {
            Self::Legacy { store_id, salt, .. } => {
                let mut output = Vec::with_capacity(LEGACY_HEADER_SIZE - 32);
                output.extend_from_slice(HEADER_MAGIC);
                output.extend_from_slice(&LEGACY_HEADER_VERSION.to_be_bytes());
                output.extend_from_slice(store_id);
                output.extend_from_slice(salt);
                output
            }
            Self::Wrapped {
                store_id,
                data_salt,
                wrapping_salt,
                nonce,
                ..
            } => {
                let mut output = Vec::with_capacity(WRAPPED_HEADER_SIZE - 48);
                output.extend_from_slice(HEADER_MAGIC);
                output.extend_from_slice(&HEADER_VERSION.to_be_bytes());
                output.extend_from_slice(store_id);
                output.extend_from_slice(data_salt);
                output.extend_from_slice(wrapping_salt);
                output.extend_from_slice(nonce);
                output
            }
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut output = self.authenticated_bytes();
        match self {
            Self::Legacy { tag, .. } => output.extend_from_slice(tag),
            Self::Wrapped {
                wrapped_data_key, ..
            } => output.extend_from_slice(wrapped_data_key),
        }
        output
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < 10 || &input[..8] != HEADER_MAGIC {
            return Err(Error::Integrity);
        }
        let version = u16::from_be_bytes(input[8..10].try_into().map_err(|_| Error::Integrity)?);
        match version {
            LEGACY_HEADER_VERSION if input.len() == LEGACY_HEADER_SIZE => Ok(Self::Legacy {
                store_id: input[10..26].try_into().map_err(|_| Error::Integrity)?,
                salt: input[26..58].try_into().map_err(|_| Error::Integrity)?,
                tag: input[58..90].try_into().map_err(|_| Error::Integrity)?,
            }),
            HEADER_VERSION if input.len() == WRAPPED_HEADER_SIZE => Ok(Self::Wrapped {
                store_id: input[10..26].try_into().map_err(|_| Error::Integrity)?,
                data_salt: input[26..58].try_into().map_err(|_| Error::Integrity)?,
                wrapping_salt: input[58..90].try_into().map_err(|_| Error::Integrity)?,
                nonce: input[90..114].try_into().map_err(|_| Error::Integrity)?,
                wrapped_data_key: input[114..162].try_into().map_err(|_| Error::Integrity)?,
            }),
            LEGACY_HEADER_VERSION | HEADER_VERSION => Err(Error::Integrity),
            _ => Err(Error::UnsupportedFormat),
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Envelope {
    pub(crate) kind: ValueKind,
    pub(crate) expires_at_ms: Option<i64>,
    pub(crate) plaintext_len: u64,
    pub(crate) revision: [u8; 16],
    pub(crate) tenant_token: [u8; 32],
    pub(crate) nonce: [u8; 24],
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct EnvelopeMetadata {
    pub(crate) kind: ValueKind,
    pub(crate) expires_at_ms: Option<i64>,
    pub(crate) plaintext_len: u64,
    pub(crate) revision: [u8; 16],
    pub(crate) tenant_token: [u8; 32],
    pub(crate) nonce: [u8; 24],
}

/// An owned plaintext buffer that wipes its full allocation when dropped.
///
/// The allocation can be released only after successful in-place encryption.
pub(crate) struct PlaintextBuffer {
    buffer: Vec<u8>,
    value_offset: usize,
}

impl PlaintextBuffer {
    pub(crate) fn with_record_prefix(buffer: Vec<u8>) -> Result<Self, Error> {
        let mut plaintext = Self {
            buffer,
            value_offset: RECORD_PREFIX_SIZE,
        };
        if plaintext.buffer.len() < RECORD_PREFIX_SIZE {
            return Err(Error::BackendState("record prefix headroom is unavailable"));
        }
        plaintext.buffer[..RECORD_PREFIX_SIZE].fill(0);
        Ok(plaintext)
    }

    pub(crate) fn from_value(value: Vec<u8>) -> Self {
        Self {
            buffer: value,
            value_offset: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.buffer.len().saturating_sub(self.value_offset)
    }

    pub(crate) fn value_mut(&mut self) -> Result<&mut [u8], Error> {
        self.buffer
            .get_mut(self.value_offset..)
            .ok_or(Error::BackendState("plaintext offset is invalid"))
    }

    pub(crate) fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }

    pub(crate) fn into_record_buffer(mut self) -> Result<Self, Error> {
        if self.value_offset == RECORD_PREFIX_SIZE {
            self.value_offset = 0;
            return Ok(self);
        }
        let value = self
            .buffer
            .get(self.value_offset..)
            .ok_or(Error::BackendState("plaintext offset is invalid"))?;
        let mut record = vec![0; RECORD_PREFIX_SIZE];
        record
            .try_reserve(value.len())
            .map_err(|_| Error::Configuration("value is too large"))?;
        record.extend_from_slice(value);
        self.buffer.zeroize();
        self.buffer = record;
        self.value_offset = 0;
        Ok(self)
    }

    pub(crate) fn into_ciphertext(mut self) -> Result<Vec<u8>, Error> {
        if self.value_offset != 0 {
            return Err(Error::BackendState("plaintext has not been encrypted"));
        }
        Ok(std::mem::take(&mut self.buffer))
    }

    pub(crate) fn zeroize(self) {
        drop(self);
    }
}

impl Drop for PlaintextBuffer {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

/// A validated, allocation-free view over a stored record envelope.
pub(crate) struct EnvelopeRef<'a> {
    metadata: EnvelopeMetadata,
    pub(crate) ciphertext: &'a [u8],
}

impl<'a> EnvelopeRef<'a> {
    pub(crate) fn parse(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < RECORD_PREFIX_SIZE || &input[..8] != RECORD_MAGIC {
            return Err(Error::Integrity);
        }
        let version = u16::from_be_bytes(input[8..10].try_into().map_err(|_| Error::Integrity)?);
        if version != RECORD_VERSION {
            return Err(Error::UnsupportedFormat);
        }
        let kind = ValueKind::try_from(input[10])?;
        let raw_expiry =
            i64::from_be_bytes(input[11..19].try_into().map_err(|_| Error::Integrity)?);
        if raw_expiry < -1 {
            return Err(Error::Integrity);
        }
        let plaintext_len =
            u64::from_be_bytes(input[19..27].try_into().map_err(|_| Error::Integrity)?);
        let max_plaintext = u64::try_from(MAX_VALUE_SIZE).map_err(|_| Error::Integrity)?;
        if plaintext_len > max_plaintext {
            return Err(Error::Integrity);
        }
        let ciphertext_len =
            u64::from_be_bytes(input[99..107].try_into().map_err(|_| Error::Integrity)?);
        let ciphertext_len = usize::try_from(ciphertext_len).map_err(|_| Error::Integrity)?;
        if ciphertext_len > MAX_VALUE_SIZE + 16
            || RECORD_PREFIX_SIZE.checked_add(ciphertext_len) != Some(input.len())
            || ciphertext_len != usize::try_from(plaintext_len).map_err(|_| Error::Integrity)? + 16
        {
            return Err(Error::Integrity);
        }
        Ok(Self {
            metadata: EnvelopeMetadata {
                kind,
                expires_at_ms: (raw_expiry >= 0).then_some(raw_expiry),
                plaintext_len,
                revision: input[27..43].try_into().map_err(|_| Error::Integrity)?,
                tenant_token: input[43..75].try_into().map_err(|_| Error::Integrity)?,
                nonce: input[75..99].try_into().map_err(|_| Error::Integrity)?,
            },
            ciphertext: &input[RECORD_PREFIX_SIZE..],
        })
    }

    pub(crate) fn metadata(&self) -> EnvelopeMetadata {
        self.metadata
    }

    #[cfg(test)]
    pub(crate) fn expires_at_ms(&self) -> Option<i64> {
        self.metadata.expires_at_ms
    }

    #[cfg(test)]
    pub(crate) fn revision(&self) -> &[u8; 16] {
        &self.metadata.revision
    }
}

#[cfg(test)]
impl Envelope {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.ciphertext.len() > MAX_VALUE_SIZE + 16 {
            return Err(Error::Configuration("value is too large"));
        }
        let ciphertext_len = u64::try_from(self.ciphertext.len())
            .map_err(|_| Error::Configuration("value is too large"))?;
        let mut output = Vec::with_capacity(RECORD_PREFIX_SIZE + self.ciphertext.len());
        output.extend_from_slice(RECORD_MAGIC);
        output.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        output.push(self.kind as u8);
        output.extend_from_slice(&self.expires_at_ms.unwrap_or(-1).to_be_bytes());
        output.extend_from_slice(&self.plaintext_len.to_be_bytes());
        output.extend_from_slice(&self.revision);
        output.extend_from_slice(&self.tenant_token);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&ciphertext_len.to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        let envelope = EnvelopeRef::parse(input)?;
        let metadata = envelope.metadata();
        Ok(Self {
            kind: metadata.kind,
            expires_at_ms: metadata.expires_at_ms,
            plaintext_len: metadata.plaintext_len,
            revision: metadata.revision,
            tenant_token: metadata.tenant_token,
            nonce: metadata.nonce,
            ciphertext: envelope.ciphertext.to_vec(),
        })
    }
}

pub(crate) fn encode_record_prefix(
    output: &mut [u8],
    metadata: &EnvelopeMetadata,
    ciphertext_len: u64,
) {
    output[..8].copy_from_slice(RECORD_MAGIC);
    output[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
    output[10] = metadata.kind as u8;
    output[11..19].copy_from_slice(&metadata.expires_at_ms.unwrap_or(-1).to_be_bytes());
    output[19..27].copy_from_slice(&metadata.plaintext_len.to_be_bytes());
    output[27..43].copy_from_slice(&metadata.revision);
    output[43..75].copy_from_slice(&metadata.tenant_token);
    output[75..99].copy_from_slice(&metadata.nonce);
    output[99..107].copy_from_slice(&ciphertext_len.to_be_bytes());
}

pub(crate) fn record_aad(
    store_id: &[u8; 16],
    record_id: &[u8; 32],
    metadata: &EnvelopeMetadata,
) -> [u8; RECORD_AAD_SIZE] {
    let mut aad = [0_u8; RECORD_AAD_SIZE];
    let mut offset = 0;
    for value in [
        RECORD_AAD_DOMAIN.as_slice(),
        store_id.as_slice(),
        record_id.as_slice(),
        &[metadata.kind as u8],
        &metadata.expires_at_ms.unwrap_or(-1).to_be_bytes(),
        &metadata.plaintext_len.to_be_bytes(),
        metadata.revision.as_slice(),
        metadata.tenant_token.as_slice(),
    ] {
        aad[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();
    }
    aad
}

pub(crate) fn expiry_index_key(
    expires_at_ms: i64,
    record_id: &[u8; 32],
    revision: &[u8; 16],
) -> [u8; 56] {
    let mut key = [0_u8; 56];
    key[..8].copy_from_slice(&expires_at_ms.to_be_bytes());
    key[8..40].copy_from_slice(record_id);
    key[40..].copy_from_slice(revision);
    key
}

pub(crate) fn decode_expiry_index_key(input: &[u8]) -> Result<(i64, [u8; 32], [u8; 16]), Error> {
    if input.len() != 56 {
        return Err(Error::Integrity);
    }
    let expires_at_ms = i64::from_be_bytes(input[..8].try_into().map_err(|_| Error::Integrity)?);
    if expires_at_ms < 0 {
        return Err(Error::Integrity);
    }
    Ok((
        expires_at_ms,
        input[8..40].try_into().map_err(|_| Error::Integrity)?,
        input[40..].try_into().map_err(|_| Error::Integrity)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{Envelope, EnvelopeRef, Header, RECORD_PREFIX_SIZE, ValueKind};

    #[test]
    fn header_round_trip_and_rejects_wrong_length() {
        let header = Header::Legacy {
            store_id: [1; 16],
            salt: [2; 32],
            tag: [3; 32],
        };
        let encoded = header.encode();
        let decoded = Header::decode(&encoded).expect("valid header");
        assert_eq!(decoded.store_id(), header.store_id());
        assert!(Header::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut unsupported = encoded;
        unsupported[8..10].copy_from_slice(&3_u16.to_be_bytes());
        assert!(matches!(
            Header::decode(&unsupported),
            Err(crate::error::Error::UnsupportedFormat)
        ));
    }

    #[test]
    fn record_round_trip_and_bounded_lengths() {
        let record = Envelope {
            kind: ValueKind::Bytes,
            expires_at_ms: Some(42),
            plaintext_len: 3,
            revision: [4; 16],
            tenant_token: [7; 32],
            nonce: [5; 24],
            ciphertext: vec![6; 19],
        };
        let encoded = record.encode().expect("valid record");
        let borrowed = EnvelopeRef::parse(&encoded).expect("borrowed record");
        assert_eq!(
            borrowed.ciphertext.as_ptr(),
            encoded[RECORD_PREFIX_SIZE..].as_ptr()
        );
        let decoded = Envelope::decode(&encoded).expect("valid record");
        assert_eq!(decoded.expires_at_ms, Some(42));
        assert_eq!(decoded.ciphertext, record.ciphertext);

        let mut malformed = encoded;
        malformed[99..107].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Envelope::decode(&malformed).is_err());

        let mut unsupported = record.encode().expect("valid record");
        unsupported[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            Envelope::decode(&unsupported),
            Err(crate::error::Error::UnsupportedFormat)
        ));
    }

    #[test]
    fn arbitrary_short_inputs_never_panic() {
        for length in 0..256 {
            let bytes = (0..length)
                .map(|offset| u8::try_from((length * 31 + offset * 17) % 256).expect("byte"))
                .collect::<Vec<_>>();
            let _ = Header::decode(&bytes);
            let _ = Envelope::decode(&bytes);
        }
    }
}
