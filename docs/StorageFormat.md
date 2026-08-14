# Storage Format

Vaultlet version 0.1 supports two file containers and one Redis layout. SQLite uses
`vaultlet_metadata_v1`, `vaultlet_records_v1`, `vaultlet_catalog_v1`, and
`vaultlet_expiry_v1` tables. redb uses the corresponding dotted table names.
SQLite and redb files are not interchangeable; callers select the engine explicitly.
Vaultlet headers and envelopes are independently versioned from either container.

Redis hashes the configured namespace with SHA-256 and Base64URL-encodes the result as
a hash tag. The `vaultlet:{tag}:data` hash stores the schema marker, wrapped store
header, record envelopes, per-record index descriptors, and encrypted catalogue-key
envelopes. `vaultlet:{tag}:catalog` and `vaultlet:{tag}:expiry` are score-zero sorted
sets whose binary members use lexical ordering. The catalogue member is the 32-byte
tenant token followed by the 32-byte record ID. The expiry member uses the same
56-byte ordering key documented below. Lua scripts keep all three keys consistent in
one Redis operation; successful mutations are acknowledged only after `WAITAOF`
confirms local AOF persistence.

## Store header

Header version 2 contains an eight-byte magic value, a big-endian `u16` version, a
random 16-byte store ID, a random 32-byte data salt, a random 32-byte wrapping salt,
a random 24-byte XChaCha20 nonce, and a 48-byte authenticated encryption of the
32-byte internal data key. The application master key is not stored. The header
prefix is additional authenticated data for key wrapping. A malformed header fails
with `IntegrityError`; an unknown version fails with `UnsupportedFormatError`; a
header that cannot be opened by the supplied master key fails with `InvalidKeyError`.

## Records

Record-table keys are 32-byte HMAC tokens over a tenant token and user key. Raw tenant
IDs and key names are never persisted.

Each value begins with an eight-byte magic value and big-endian version, followed by:

- value kind (`bytes` or JSON);
- optional UTC epoch expiry in milliseconds, encoded as `-1` when absent;
- plaintext byte length;
- random 16-byte revision;
- blinded 32-byte tenant token;
- random 24-byte XChaCha20 nonce;
- ciphertext length and ciphertext with its 16-byte Poly1305 tag.

Lengths are bounded before allocation. Version 0.1 supports encoded plaintext values
up to 64 MiB and authenticates/decrypts a whole value in memory.

The canonical AEAD additional data includes a fixed domain string, store ID, record
ID, kind, expiry, plaintext length, revision, and tenant token. This prevents a valid
ciphertext from being reassigned to a different store, logical key, type, expiry, or
revision.

JSON plaintext begins with codec version 1 and contains MessagePack for the documented
JSON subset. It is separate from the record-envelope version. Reads validate that
MessagePack directly and retain a zeroizing buffer behind immutable native views;
the persisted representation is unchanged.

## Encrypted key catalogue

Each live record has one catalogue row in the same transaction. Its index combines a
blinded tenant token and record ID. Its value is a small authenticated envelope whose
plaintext is the UTF-8 key name and whose expiry and revision match the value record.
Enumeration decrypts and validates these catalogue envelopes, verifies their derived
record IDs, excludes expired rows, and sorts the bounded result lexically. Backends
apply the caller's capped limit to the opaque index before loading envelopes and use
one encrypted lookahead row to indicate that further catalogue entries exist. Raw key
names are never stored in the database container.

## Expiry index

Expiry keys sort by big-endian epoch milliseconds, record ID, and revision. Empty
values make the index compact. The index is not trusted: maintenance retrieves the
record, parses and authenticates its envelope, confirms expiry and revision, and
performs comparison and deletion in one bounded batch transaction. Lazy reads, key
enumeration, background maintenance, and explicit purge use the same guarded batch
cleanup contract. An overwrite replaces the old index entry atomically with the
record.
