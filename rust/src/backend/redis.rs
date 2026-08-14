use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use base64::Engine as _;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{ConnectionAddr, FromRedisValue, IntoConnectionInfo, RedisError, Script};
use sha2::{Digest, Sha256};

use super::{
    Backend, CatalogEntry, CatalogPage, CleanupCandidate, ExpiryCandidate, ExpiryRecord, Mutation,
    RecordId, TenantToken, decode_put_envelopes,
};
use crate::error::Error;
use crate::format::{decode_expiry_index_key, expiry_index_key};

const SCHEMA: &[u8] = b"vaultlet.redis.v1";
const SCHEMA_FIELD: &[u8] = b"schema";
const HEADER_FIELD: &[u8] = b"header";
const RECORD_FIELD_PREFIX: u8 = b'r';
const CATALOG_MEMBER_SIZE: usize = 64;
const EXPIRY_MEMBER_SIZE: usize = 56;
const EXPIRING_INDEX_SIZE: usize = CATALOG_MEMBER_SIZE + EXPIRY_MEMBER_SIZE;
const EXPIRY_BATCH_LIMIT: usize = 10_000;

const HEADER_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], ARGV[1])
local header = redis.call('HGET', KEYS[1], ARGV[2])
if header then
    if not schema then
        return redis.error_reply('VLT_INTEGRITY')
    end
    if schema ~= ARGV[3] then
        return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
    end
    return {0, header}
end
if schema and schema ~= ARGV[3] then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
if schema then
    return redis.error_reply('VLT_INTEGRITY')
end
if redis.call('HLEN', KEYS[1]) ~= 0
    or redis.call('ZCARD', KEYS[2]) ~= 0
    or redis.call('ZCARD', KEYS[3]) ~= 0 then
    return redis.error_reply('VLT_INTEGRITY')
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3], ARGV[2], ARGV[4])
return {1, ARGV[4]}
"#;

const REPLACE_HEADER_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], ARGV[1])
if not schema then
    return redis.error_reply('VLT_INTEGRITY')
end
if schema ~= ARGV[2] then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
local header = redis.call('HGET', KEYS[1], ARGV[3])
if not header then
    return redis.error_reply('VLT_INTEGRITY')
end
if header ~= ARGV[4] then
    return 0
end
redis.call('HSET', KEYS[1], ARGV[3], ARGV[5])
return 1
"#;

const MUTATE_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], 'schema')
if not schema or not redis.call('HGET', KEYS[1], 'header') then
    return redis.error_reply('VLT_INTEGRITY')
end
if schema ~= 'vaultlet.redis.v1' then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
local count = tonumber(ARGV[1])
local width = 5
local loaded = {}
local revisions = {}
local results = {}

local function record_field(record_id)
    return 'r' .. record_id
end

local function index_field(record_id)
    return 'i' .. record_id
end

local function validate_current(record_id)
    local record_key = record_field(record_id)
    if loaded[record_key] then
        return revisions[record_key]
    end
    local envelope = redis.call('HGET', KEYS[1], record_key)
    local index = redis.call('HGET', KEYS[1], index_field(record_id))
    if (envelope and not index) or (index and not envelope) then
        error('VLT_INTEGRITY')
    end
    if envelope then
        if string.len(envelope) < 43 then
            error('VLT_INTEGRITY')
        end
        local index_length = string.len(index)
        if index_length ~= 64 and index_length ~= 120 then
            error('VLT_INTEGRITY')
        end
        local catalog_member = string.sub(index, 1, 64)
        if string.sub(catalog_member, 33, 64) ~= record_id
            or not redis.call('HGET', KEYS[1], 'c' .. catalog_member)
            or not redis.call('ZSCORE', KEYS[2], catalog_member) then
            error('VLT_INTEGRITY')
        end
        if index_length == 120 then
            local expiry_member = string.sub(index, 65, 120)
            if string.sub(expiry_member, 9, 40) ~= record_id
                or string.sub(expiry_member, 41, 56) ~= string.sub(envelope, 28, 43)
                or not redis.call('ZSCORE', KEYS[3], expiry_member) then
                error('VLT_INTEGRITY')
            end
        end
        revisions[record_key] = string.sub(envelope, 28, 43)
    else
        revisions[record_key] = false
    end
    loaded[record_key] = true
    return revisions[record_key]
end

for item = 0, count - 1 do
    local base = 2 + item * width
    local operation = ARGV[base]
    local record_id = ARGV[base + 1]
    if string.len(record_id) ~= 32 then
        error('VLT_INTEGRITY')
    end
    local current = validate_current(record_id)
    if operation == 'P' then
        local envelope = ARGV[base + 2]
        local index = ARGV[base + 4]
        local revision = string.sub(envelope, 28, 43)
        local index_length = string.len(index)
        local catalog_member = string.sub(index, 1, 64)
        if string.len(envelope) < 43
            or string.len(catalog_member) ~= 64
            or string.sub(catalog_member, 33, 64) ~= record_id
            or (index_length ~= 64 and index_length ~= 120)
            or string.sub(index, 1, 64) ~= catalog_member
            or string.len(revision) ~= 16 then
            error('VLT_INTEGRITY')
        end
        if index_length == 120 then
            local expiry_member = string.sub(index, 65, 120)
            if string.sub(expiry_member, 9, 40) ~= record_id
                or string.sub(expiry_member, 41, 56) ~= revision then
                error('VLT_INTEGRITY')
            end
        end
        revisions[record_field(record_id)] = revision
        results[item + 1] = 1
    elseif operation == 'G' then
        local expected = ARGV[base + 4]
        if string.len(expected) ~= 16 then
            error('VLT_INTEGRITY')
        end
        if current == false or current ~= expected then
            local failed = {}
            for index = 1, count do
                failed[index] = 0
            end
            return failed
        end
        revisions[record_field(record_id)] = false
        results[item + 1] = 1
    elseif operation == 'D' then
        results[item + 1] = current and 1 or 0
        revisions[record_field(record_id)] = false
    else
        error('VLT_INTEGRITY')
    end
end

local function remove_current(record_id)
    local record_key = record_field(record_id)
    local index_key = index_field(record_id)
    local index = redis.call('HGET', KEYS[1], index_key)
    if not index then
        return false
    end
    local catalog_member = string.sub(index, 1, 64)
    redis.call('HDEL', KEYS[1], 'c' .. catalog_member)
    redis.call('ZREM', KEYS[2], catalog_member)
    if string.len(index) == 120 then
        redis.call('ZREM', KEYS[3], string.sub(index, 65, 120))
    end
    redis.call('HDEL', KEYS[1], record_key, index_key)
    return true
end

for item = 0, count - 1 do
    local base = 2 + item * width
    local operation = ARGV[base]
    local record_id = ARGV[base + 1]
    if operation == 'P' then
        local envelope = ARGV[base + 2]
        local key_envelope = ARGV[base + 3]
        local index = ARGV[base + 4]
        local catalog_member = string.sub(index, 1, 64)
        remove_current(record_id)
        redis.call('HSET', KEYS[1], record_field(record_id), envelope,
            index_field(record_id), index, 'c' .. catalog_member, key_envelope)
        redis.call('ZADD', KEYS[2], 0, catalog_member)
        if string.len(index) == 120 then
            redis.call('ZADD', KEYS[3], 0, string.sub(index, 65, 120))
        end
    else
        remove_current(record_id)
    end
end
return results
"#;

const LIST_CATALOG_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], 'schema')
if not schema or not redis.call('HGET', KEYS[1], 'header') then
    return redis.error_reply('VLT_INTEGRITY')
end
if schema ~= 'vaultlet.redis.v1' then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
local members = redis.call('ZRANGE', KEYS[2], ARGV[2], ARGV[3],
    'BYLEX', 'LIMIT', 0, tonumber(ARGV[4]))
local result = {}
for _, member in ipairs(members) do
    if string.len(member) ~= 64 or string.sub(member, 1, 32) ~= ARGV[1] then
        return redis.error_reply('VLT_INTEGRITY')
    end
    local record_id = string.sub(member, 33, 64)
    local key_envelope = redis.call('HGET', KEYS[1], 'c' .. member)
    local envelope = redis.call('HGET', KEYS[1], 'r' .. record_id)
    if not key_envelope or not envelope then
        return redis.error_reply('VLT_INTEGRITY')
    end
    result[#result + 1] = record_id
    result[#result + 1] = key_envelope
end
return result
"#;

const SCAN_DUE_RECORDS_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], 'schema')
if not schema or not redis.call('HGET', KEYS[1], 'header') then
    return redis.error_reply('VLT_INTEGRITY')
end
if schema ~= 'vaultlet.redis.v1' then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
local members = redis.call('ZRANGE', KEYS[2], '-', ARGV[1],
    'BYLEX', 'LIMIT', 0, tonumber(ARGV[2]))
local indexes = {}
local envelopes = {}
local total_bytes = 0
local byte_limit = tonumber(ARGV[3])
for _, member in ipairs(members) do
    if string.len(member) ~= 56 then
        return redis.error_reply('VLT_INTEGRITY')
    end
    local record_id = string.sub(member, 9, 40)
    local envelope = redis.call('HGET', KEYS[1], 'r' .. record_id)
    local next_bytes = envelope and string.len(envelope) or 0
    if #indexes > 0 and total_bytes + next_bytes > byte_limit then
        break
    end
    total_bytes = total_bytes + next_bytes
    indexes[#indexes + 1] = member
    envelopes[#envelopes + 1] = envelope or ''
end
return {indexes, envelopes}
"#;

const CLEANUP_SCRIPT: &str = r#"
local schema = redis.call('HGET', KEYS[1], 'schema')
if not schema or not redis.call('HGET', KEYS[1], 'header') then
    return redis.error_reply('VLT_INTEGRITY')
end
if schema ~= 'vaultlet.redis.v1' then
    return redis.error_reply('VLT_UNSUPPORTED_FORMAT')
end
local count = tonumber(ARGV[1])

local function validate_current(record_id)
    local envelope = redis.call('HGET', KEYS[1], 'r' .. record_id)
    local index = redis.call('HGET', KEYS[1], 'i' .. record_id)
    if (envelope and not index) or (index and not envelope) then
        error('VLT_INTEGRITY')
    end
    if not envelope then
        return false, false
    end
    if string.len(envelope) < 43
        or (string.len(index) ~= 64 and string.len(index) ~= 120)
        or string.sub(index, 33, 64) ~= record_id then
        error('VLT_INTEGRITY')
    end
    local catalog_member = string.sub(index, 1, 64)
    if not redis.call('HGET', KEYS[1], 'c' .. catalog_member)
        or not redis.call('ZSCORE', KEYS[2], catalog_member) then
        error('VLT_INTEGRITY')
    end
    if string.len(index) == 120
        and not redis.call('ZSCORE', KEYS[3], string.sub(index, 65, 120)) then
        error('VLT_INTEGRITY')
    end
    return envelope, index
end

for item = 0, count - 1 do
    local base = 2 + item * 2
    local member = ARGV[base]
    if string.len(member) ~= 56 then
        error('VLT_INTEGRITY')
    end
    if ARGV[base + 1] == '1' then
        local envelope, index = validate_current(string.sub(member, 9, 40))
        if envelope and string.sub(envelope, 28, 43) == string.sub(member, 41, 56)
            and (string.len(index) ~= 120 or string.sub(index, 65, 120) ~= member) then
            error('VLT_INTEGRITY')
        end
    end
end

local deleted = 0
for item = 0, count - 1 do
    local base = 2 + item * 2
    local member = ARGV[base]
    local record_id = string.sub(member, 9, 40)
    local revision = string.sub(member, 41, 56)
    redis.call('ZREM', KEYS[3], member)
    if ARGV[base + 1] == '1' then
        local envelope = redis.call('HGET', KEYS[1], 'r' .. record_id)
        if envelope and string.sub(envelope, 28, 43) == revision then
            local index = redis.call('HGET', KEYS[1], 'i' .. record_id)
            local catalog_member = string.sub(index, 1, 64)
            redis.call('HDEL', KEYS[1], 'c' .. catalog_member,
                'r' .. record_id, 'i' .. record_id)
            redis.call('ZREM', KEYS[2], catalog_member)
            if string.len(index) == 120 then
                redis.call('ZREM', KEYS[3], string.sub(index, 65, 120))
            end
            deleted = deleted + 1
        end
    end
end
return deleted
"#;

pub(crate) struct RedisConfig {
    pub(crate) endpoint: String,
    pub(crate) namespace: String,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) connect_timeout: Duration,
    pub(crate) response_timeout: Duration,
    pub(crate) durability_timeout: Duration,
}

pub(crate) struct RedisBackend {
    data_key: Vec<u8>,
    catalog_key: Vec<u8>,
    expiry_key: Vec<u8>,
    reader: ArcSwapOption<ConnectionManager>,
    writer: ArcSwapOption<ConnectionManager>,
    durability_timeout_ms: u64,
    closed: AtomicBool,
}

impl RedisBackend {
    pub(crate) async fn open(config: RedisConfig) -> Result<Arc<Self>, Error> {
        if config.namespace.is_empty()
            || config.namespace.contains('\0')
            || config.namespace.len() > 1024
        {
            return Err(Error::Configuration(
                "Redis namespace must contain between 1 and 1024 UTF-8 bytes",
            ));
        }
        let durability_timeout_ms = u64::try_from(config.durability_timeout.as_millis())
            .map_err(|_| Error::Configuration("Redis durability timeout is too large"))?;
        if durability_timeout_ms == 0 {
            return Err(Error::Configuration(
                "Redis durability timeout must be at least one millisecond",
            ));
        }
        if config.connect_timeout.is_zero()
            || config.response_timeout.is_zero()
            || config.durability_timeout.is_zero()
            || config.durability_timeout >= config.response_timeout
        {
            return Err(Error::Configuration("Redis timeouts are invalid"));
        }

        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut connection_info = config
            .endpoint
            .as_str()
            .into_connection_info()
            .map_err(map_redis_error)?;
        match connection_info.addr() {
            ConnectionAddr::Tcp(_, _) => {}
            ConnectionAddr::TcpTls {
                insecure: false,
                tls_params: None,
                ..
            } => {}
            _ => {
                return Err(Error::Configuration(
                    "Redis endpoint must use redis:// or rediss:// with certificate verification",
                ));
            }
        }
        if connection_info.redis_settings().username().is_some()
            || connection_info.redis_settings().password().is_some()
        {
            return Err(Error::Configuration(
                "Redis credentials must be supplied separately from the endpoint",
            ));
        }
        let mut redis_settings = connection_info
            .redis_settings()
            .clone()
            .set_lib_name("vaultlet", env!("CARGO_PKG_VERSION"));
        if let Some(username) = config.username {
            redis_settings = redis_settings.set_username(username);
        }
        if let Some(password) = config.password {
            redis_settings = redis_settings.set_password(password);
        }
        connection_info = connection_info.set_redis_settings(redis_settings);
        let client = redis::Client::open(connection_info).map_err(map_redis_error)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(config.connect_timeout))
            .set_response_timeout(Some(config.response_timeout))
            .set_concurrency_limit(32);
        let reader = ConnectionManager::new_with_config(client.clone(), manager_config.clone())
            .await
            .map_err(map_redis_error)?;
        let mut writer = ConnectionManager::new_with_config(client, manager_config)
            .await
            .map_err(map_redis_error)?;
        let durability: (usize, usize) = redis::cmd("WAITAOF")
            .arg(1)
            .arg(0)
            .arg(durability_timeout_ms)
            .query_async(&mut writer)
            .await
            .map_err(map_redis_error)?;
        if durability.0 < 1 {
            return Err(Error::BackendState(
                "Redis did not confirm local AOF durability",
            ));
        }

        let digest = Sha256::digest(config.namespace.as_bytes());
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        let prefix = format!("vaultlet:{{{tag}}}");
        Ok(Arc::new(Self {
            data_key: format!("{prefix}:data").into_bytes(),
            catalog_key: format!("{prefix}:catalog").into_bytes(),
            expiry_key: format!("{prefix}:expiry").into_bytes(),
            reader: ArcSwapOption::new(Some(Arc::new(reader))),
            writer: ArcSwapOption::new(Some(Arc::new(writer))),
            durability_timeout_ms,
            closed: AtomicBool::new(false),
        }))
    }

    fn reader(&self) -> Result<ConnectionManager, Error> {
        self.connection(&self.reader)
    }

    fn writer(&self) -> Result<ConnectionManager, Error> {
        self.connection(&self.writer)
    }

    fn connection(
        &self,
        state: &ArcSwapOption<ConnectionManager>,
    ) -> Result<ConnectionManager, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        state
            .load_full()
            .map(|manager| manager.as_ref().clone())
            .ok_or(Error::Closed)
    }

    async fn invoke_read<T: FromRedisValue>(
        &self,
        source: &str,
        keys: &[&[u8]],
        args: &[Vec<u8>],
    ) -> Result<T, Error> {
        let script = Script::new(source);
        let mut invocation = script.prepare_invoke();
        for key in keys {
            invocation.key(*key);
        }
        for arg in args {
            invocation.arg(arg.as_slice());
        }
        invocation
            .invoke_async(&mut self.reader()?)
            .await
            .map_err(map_redis_error)
    }

    async fn invoke_durable<T: FromRedisValue>(
        &self,
        source: &str,
        keys: &[&[u8]],
        args: &[Vec<u8>],
    ) -> Result<T, Error> {
        let script = Script::new(source);
        let mut connection = self.writer()?;
        for attempt in 0..2 {
            let mut evaluate = redis::cmd("EVALSHA");
            evaluate.arg(script.get_hash()).arg(keys.len());
            for key in keys {
                evaluate.arg(*key);
            }
            for arg in args {
                evaluate.arg(arg.as_slice());
            }
            let mut pipeline = redis::pipe();
            pipeline
                .add_command(evaluate)
                .cmd("WAITAOF")
                .arg(1)
                .arg(0)
                .arg(self.durability_timeout_ms);
            let response: Result<(T, (usize, usize)), RedisError> =
                pipeline.query_async(&mut connection).await;
            match response {
                Ok((value, durability)) => {
                    if durability.0 < 1 {
                        return Err(Error::BackendState(
                            "Redis did not confirm local AOF durability",
                        ));
                    }
                    return Ok(value);
                }
                Err(error) if attempt == 0 && is_missing_script(&error) => {
                    script
                        .load_async(&mut connection)
                        .await
                        .map_err(map_redis_error)?;
                }
                Err(error) => return Err(map_redis_error(error)),
            }
        }
        Err(Error::BackendState("Redis script could not be loaded"))
    }
}

#[async_trait]
impl Backend for RedisBackend {
    async fn load_or_initialize_header(&self, candidate: Vec<u8>) -> Result<Vec<u8>, Error> {
        let args = vec![
            SCHEMA_FIELD.to_vec(),
            HEADER_FIELD.to_vec(),
            SCHEMA.to_vec(),
            candidate,
        ];
        let (_, header): (usize, Vec<u8>) = self
            .invoke_durable(
                HEADER_SCRIPT,
                &[
                    self.data_key.as_slice(),
                    self.catalog_key.as_slice(),
                    self.expiry_key.as_slice(),
                ],
                &args,
            )
            .await?;
        Ok(header)
    }

    async fn replace_header(&self, expected: Vec<u8>, replacement: Vec<u8>) -> Result<bool, Error> {
        let args = vec![
            SCHEMA_FIELD.to_vec(),
            SCHEMA.to_vec(),
            HEADER_FIELD.to_vec(),
            expected,
            replacement,
        ];
        self.invoke_durable::<usize>(REPLACE_HEADER_SCRIPT, &[self.data_key.as_slice()], &args)
            .await
            .map(|changed| changed == 1)
    }

    async fn read_many(&self, record_ids: Vec<RecordId>) -> Result<Vec<Option<Vec<u8>>>, Error> {
        if record_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = redis::cmd("HMGET");
        command.arg(self.data_key.as_slice());
        for record_id in &record_ids {
            command.arg(&prefixed_field(RECORD_FIELD_PREFIX, record_id));
        }
        command
            .query_async(&mut self.reader()?)
            .await
            .map_err(map_redis_error)
    }

    async fn read_one(&self, record_id: RecordId) -> Result<Option<Vec<u8>>, Error> {
        redis::cmd("HGET")
            .arg(self.data_key.as_slice())
            .arg(&prefixed_field(RECORD_FIELD_PREFIX, &record_id))
            .query_async(&mut self.reader()?)
            .await
            .map_err(map_redis_error)
    }

    async fn list_catalog(
        &self,
        tenant_token: TenantToken,
        after: Option<RecordId>,
        limit: usize,
    ) -> Result<CatalogPage, Error> {
        let mut start = Vec::with_capacity(65);
        start.push(if after.is_some() { b'(' } else { b'[' });
        start.extend_from_slice(&tenant_token);
        start.extend_from_slice(&after.unwrap_or([0; 32]));
        let mut end = Vec::with_capacity(65);
        end.push(b'[');
        end.extend_from_slice(&tenant_token);
        end.extend_from_slice(&[u8::MAX; 32]);
        let args = vec![
            tenant_token.to_vec(),
            start,
            end,
            CatalogPage::fetch_limit(limit)?.to_string().into_bytes(),
        ];
        let raw: Vec<Vec<u8>> = self
            .invoke_read(
                LIST_CATALOG_SCRIPT,
                &[self.data_key.as_slice(), self.catalog_key.as_slice()],
                &args,
            )
            .await?;
        if raw.len() % 2 != 0 {
            return Err(Error::Integrity);
        }
        let entries = raw
            .chunks_exact(2)
            .map(|pair| {
                Ok(CatalogEntry {
                    record_id: pair[0]
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Integrity)?,
                    key_envelope: pair[1].clone(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        CatalogPage::from_lookahead(entries, limit)
    }

    async fn mutate(&self, mutations: Vec<Mutation>) -> Result<Vec<bool>, Error> {
        let mut args = Vec::with_capacity(1 + mutations.len() * 5);
        args.push(mutations.len().to_string().into_bytes());
        for mutation in mutations {
            match mutation {
                Mutation::Put {
                    record_id,
                    envelope,
                    tenant_token,
                    key_envelope,
                } => {
                    let metadata = decode_put_envelopes(&envelope, &key_envelope, &tenant_token)?;
                    let catalog_member = catalog_key(&tenant_token, &record_id);
                    let mut index = Vec::with_capacity(EXPIRING_INDEX_SIZE);
                    index.extend_from_slice(&catalog_member);
                    if let Some(expires_at_ms) = metadata.expires_at_ms {
                        index.extend_from_slice(&expiry_index_key(
                            expires_at_ms,
                            &record_id,
                            &metadata.revision,
                        ));
                    }
                    args.extend([
                        b"P".to_vec(),
                        record_id.to_vec(),
                        envelope,
                        key_envelope,
                        index,
                    ]);
                }
                Mutation::DeleteGuarded {
                    record_id,
                    revision,
                } => args.extend([
                    b"G".to_vec(),
                    record_id.to_vec(),
                    Vec::new(),
                    Vec::new(),
                    revision.to_vec(),
                ]),
                Mutation::DeleteAny { record_id } => args.extend([
                    b"D".to_vec(),
                    record_id.to_vec(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ]),
            }
        }
        let results: Vec<usize> = self
            .invoke_durable(
                MUTATE_SCRIPT,
                &[
                    self.data_key.as_slice(),
                    self.catalog_key.as_slice(),
                    self.expiry_key.as_slice(),
                ],
                &args,
            )
            .await?;
        Ok(results.into_iter().map(|result| result == 1).collect())
    }

    async fn scan_due(&self, now_ms: i64, limit: usize) -> Result<Vec<ExpiryCandidate>, Error> {
        let limit = limit.min(EXPIRY_BATCH_LIMIT);
        let end = expiry_end_bound(now_ms);
        let raw: Vec<Vec<u8>> = redis::cmd("ZRANGE")
            .arg(self.expiry_key.as_slice())
            .arg(b"-".as_slice())
            .arg(end)
            .arg("BYLEX")
            .arg("LIMIT")
            .arg(0)
            .arg(limit)
            .query_async(&mut self.reader()?)
            .await
            .map_err(map_redis_error)?;
        raw.into_iter().map(expiry_candidate).collect()
    }

    async fn scan_due_records(
        &self,
        now_ms: i64,
        record_limit: usize,
        byte_limit: usize,
    ) -> Result<Vec<ExpiryRecord>, Error> {
        let record_limit = record_limit.min(EXPIRY_BATCH_LIMIT);
        let args = vec![
            expiry_end_bound(now_ms),
            record_limit.to_string().into_bytes(),
            byte_limit.to_string().into_bytes(),
        ];
        let (indexes, envelopes): (Vec<Vec<u8>>, Vec<Vec<u8>>) = self
            .invoke_read(
                SCAN_DUE_RECORDS_SCRIPT,
                &[self.data_key.as_slice(), self.expiry_key.as_slice()],
                &args,
            )
            .await?;
        if indexes.len() != envelopes.len() {
            return Err(Error::Integrity);
        }
        indexes
            .into_iter()
            .zip(envelopes)
            .map(|(index, envelope)| {
                Ok(ExpiryRecord {
                    candidate: expiry_candidate(index)?,
                    envelope: (!envelope.is_empty()).then_some(envelope),
                })
            })
            .collect()
    }

    async fn cleanup_candidates(&self, candidates: Vec<CleanupCandidate>) -> Result<usize, Error> {
        let mut args = Vec::with_capacity(1 + candidates.len() * 2);
        args.push(candidates.len().to_string().into_bytes());
        for cleanup in candidates {
            args.push(cleanup.candidate.index_key.to_vec());
            args.push(if cleanup.delete_current {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            });
        }
        self.invoke_durable(
            CLEANUP_SCRIPT,
            &[
                self.data_key.as_slice(),
                self.catalog_key.as_slice(),
                self.expiry_key.as_slice(),
            ],
            &args,
        )
        .await
    }

    async fn close(&self) -> Result<(), Error> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.reader.store(None);
        self.writer.store(None);
        Ok(())
    }
}

fn prefixed_field(prefix: u8, record_id: &RecordId) -> [u8; 33] {
    let mut field = [0_u8; 33];
    field[0] = prefix;
    field[1..].copy_from_slice(record_id);
    field
}

fn catalog_key(tenant_token: &TenantToken, record_id: &RecordId) -> [u8; CATALOG_MEMBER_SIZE] {
    let mut key = [0_u8; CATALOG_MEMBER_SIZE];
    key[..32].copy_from_slice(tenant_token);
    key[32..].copy_from_slice(record_id);
    key
}

fn expiry_end_bound(now_ms: i64) -> Vec<u8> {
    let mut bound = Vec::with_capacity(EXPIRY_MEMBER_SIZE + 1);
    bound.push(b'[');
    bound.extend_from_slice(&now_ms.to_be_bytes());
    bound.extend_from_slice(&[u8::MAX; 48]);
    bound
}

fn expiry_candidate(index_key: Vec<u8>) -> Result<ExpiryCandidate, Error> {
    let (expires_at_ms, record_id, revision) = decode_expiry_index_key(&index_key)?;
    Ok(ExpiryCandidate {
        index_key: index_key.try_into().map_err(|_| Error::Integrity)?,
        expires_at_ms,
        record_id,
        revision,
    })
}

fn is_missing_script(error: &RedisError) -> bool {
    error.to_string().to_ascii_lowercase().contains("noscript")
}

fn map_redis_error(error: RedisError) -> Error {
    let message = error.to_string();
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("vlt_unsupported_format") {
        Error::UnsupportedFormat
    } else if normalized.contains("vlt_integrity") || normalized.contains("wrongtype") {
        Error::Integrity
    } else {
        Error::backend(error)
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{RedisBackend, RedisConfig};
    use crate::backend::Backend;
    use crate::backend::tests::backend_contract;

    fn test_config(namespace: String) -> RedisConfig {
        RedisConfig {
            endpoint: env::var("VAULTLET_TEST_REDIS_ENDPOINT")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned()),
            namespace,
            username: env::var("VAULTLET_TEST_REDIS_USERNAME").ok(),
            password: env::var("VAULTLET_TEST_REDIS_PASSWORD").ok(),
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(30),
            durability_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    #[ignore = "requires an ephemeral Redis 7.2+ server with AOF enabled"]
    async fn redis_backend_obeys_contract_and_reopens() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let namespace = format!("vaultlet-test-{}-{unique}", std::process::id());
        let backend = RedisBackend::open(test_config(namespace.clone()))
            .await
            .expect("open");
        redis::cmd("SCRIPT")
            .arg("FLUSH")
            .query_async::<()>(&mut backend.writer().expect("writer"))
            .await
            .expect("flush scripts");
        backend_contract(Arc::clone(&backend) as Arc<dyn Backend>).await;
        backend.close().await.expect("close");

        let reopened = RedisBackend::open(test_config(namespace))
            .await
            .expect("reopen");
        assert_eq!(
            reopened
                .load_or_initialize_header(vec![8, 8, 8])
                .await
                .expect("header"),
            vec![3, 2, 1]
        );
        reopened.close().await.expect("close");
    }
}
