[![Activeledger](https://www.activeledger.io/wp-content/uploads/2018/09/Asset-1.png)](https://activeledger.io/)

# Activeledger SDK for C#

Build, sign and submit Activeledger transactions from .NET, with support for
post-quantum identities.

- **ML-DSA-65** and **Falcon-512** post-quantum identities
- **secp256k1** for small payloads, hardware keys and existing identities
- Canonical JSON that reproduces the exact bytes the ledger signs
- Server-sent event subscriptions
- One dependency (BouncyCastle), pure managed code, no native libraries
- `netstandard2.0` and `net8.0`, so .NET Framework, Unity, Mono and modern
  .NET all work

## Install

```bash
dotnet add package Activeledger.SDK
```

## Quick start

```csharp
using Activeledger;

using var client = new ActiveledgerClient("http://localhost:5260");

// A post-quantum identity
var key = KeyPair.Generate(KeyType.MlDsa65);
var identity = await client.OnboardAsync(key);

Console.WriteLine(identity.StreamId);

// A transaction signed by it
var tx = Transaction.Builder()
    .Namespace("default")
    .Contract("mycontract")
    .Input(identity.StreamId, identity.Signer,
        new JsonObject().Set("amount", 100))
    .Output("someotherstream")
    .Build();

var response = await client.SubmitAsync(tx);

if (!response.Committed)
{
    // NOT the HTTP status. See "A rejected transaction is an HTTP 200" below.
    Console.WriteLine(string.Join(", ", response.Errors));
}
```

## Seeds and recovery phrases

```csharp
var key = KeyPair.FromSeed(KeyType.MlDsa65, seed);                 // 32 bytes
var key = KeyPair.FromSeed(KeyType.Falcon512, seed);               // 48 bytes
var key = KeyPair.FromPhrase(KeyType.MlDsa65, phrase);             // BIP-39
var key = KeyPair.FromPhrase(KeyType.Secp256k1, phrase, "pass");
```

The same seed gives the same identity in every Activeledger SDK, which is what
makes a seed the portable private-key format — it is how a private key moves
between languages. It matters most for PHP, whose ML-DSA-65 private key **is**
a 32-byte seed and which has no 4032-byte form at all.

A seed of the wrong length is **refused, not padded**: a padded seed is a
different identity, not a malformed one.

For `secp256k1` the seed **is** the private scalar, so it has to be a valid
one. A seed of zero, or one at or above the curve order, is refused rather
than reduced mod *n* — reducing produces a perfectly functional key belonging
to a different identity, and nothing downstream ever reports a problem.

The phrase is validated, wordlist **and** checksum. A mistyped phrase that is
not checked does not fail; it derives a valid key for an identity nobody owns,
and the only symptom is the ledger not recognising it.

`KeyPair.FromLegacyPhrase` recovers a phrase made by the older
`@activeledger/sdk-bip39` package — recovery only, never for new keys.

### The derivation

| Type | Seed from the BIP-39 seed `S` |
| --- | --- |
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

`secp256k1` deliberately does not use HKDF: the JavaScript SDK shipped that
derivation before the post-quantum types existed, so phrases are already in
use, and changing it would hand those users a different key for a phrase that
used to work.

One phrase can back all three identity types at once, since each derives its
own seed.

BouncyCastle's PBKDF2 and HKDF are used rather than the framework's.
`System.Security.Cryptography.HKDF` does not exist on `netstandard2.0`, so the
framework route would derive different keys depending on which target a
consumer built against.

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| `KeyType.MlDsa65` | `ml-dsa-65` | 1952 | 4032 | 3309 | base64 |
| `KeyType.Falcon512` | `falcon-512` | 897 | 1281 | **649–662, variable** | base64 |
| `KeyType.Secp256k1` | `secp256k1` | 33 or 65 | 32 | **~70–72, variable** | `0x` hex |
| `KeyType.Rsa` | `rsa` | — | — | — | not implemented |

**RSA is deliberately not implemented.** It is the ledger's fallback when a
transaction omits `type`, which is precisely why this SDK always sends the type
explicitly.

### Which to choose

Post-quantum if the identity must outlive a cryptographically relevant quantum
computer. secp256k1 otherwise — it is dramatically cheaper, and every byte is
stored on the ledger permanently and replicated to every node. Measured with
this SDK:

| Transaction | secp256k1 | Falcon-512 | ML-DSA-65 |
|---|---|---|---|
| Onboard | **321 B** | 2,230 B | 7,173 B |
| Transfer | **204 B** | 984 B | 4,520 B |

secp256k1 is also what hardware wallets and most HSMs speak, and it is what
existing Activeledger identities already use — so it is the only way to sign
for an identity created before post-quantum support.

Note that phone secure enclaves (Apple Secure Enclave, Android StrongBox) use
**P-256**, not secp256k1, and the ledger does not support P-256 at all.

```csharp
var mldsa  = KeyPair.Generate(KeyType.MlDsa65);
var falcon = KeyPair.Generate(KeyType.Falcon512);
var ec     = KeyPair.Generate(KeyType.Secp256k1);                    // compressed
var ecFull = KeyPair.Generate(KeyType.Secp256k1, compressed: false); // uncompressed

// Exactly the encoding the ledger stores, whichever scheme it is
string pub  = mldsa.PublicKey;    // base64
string priv = mldsa.PrivateKey;
string ecPub = ec.PublicKey;      // "0x02a1b2..."

// Round-trip a stored key
var restored = KeyPair.FromKeys(KeyType.MlDsa65, pub, priv);

// Verification only - no private key, and Sign() throws
var verifier = KeyPair.FromPublic(KeyType.MlDsa65, pub);
```

`PublicKey` and `PrivateKey` are deliberately not named for an encoding,
because it differs by scheme: base64 for the post-quantum keys, `0x`-prefixed
hex for secp256k1. Whatever they return goes into the transaction verbatim.

Things about these keys worth knowing before they cost you an afternoon.

**secp256k1 keys are hex with an `0x` prefix, not base64.** The prefix is part
of what the ledger stores, so this SDK requires it rather than tolerating its
absence — a hex string without it can decode as base64 into plausible-looking
bytes of the wrong length, which is the kind of mistake that surfaces as 1220.

**secp256k1 public keys come in two lengths**, and the ledger accepts both: 33
bytes compressed (`0x02`/`0x03`) and 65 uncompressed (`0x04`). This SDK
generates compressed by default because the key is stored forever. A length and
a point prefix that disagree is rejected by name.

**secp256k1 private keys are left-padded to 32 bytes.** A scalar with a leading
zero byte occurs about once in 400 keys, and an unpadded key is a different
value to anything reading it strictly.

**secp256k1 signatures are DER, and DER length varies** — 70, 71 and 72 bytes
all occur. A raw 64-byte `r||s` pair is not what the ledger expects.

**secp256k1 signing is deterministic (RFC 6979) and always low-S**, and this
matters in both directions:

- *Emitting* low-S is not for the ledger, which accepts either. It is for
  everything else: `@noble/curves` rejects high-S unless explicitly told not
  to, and it is the reference implementation for the JavaScript side;
  libsecp256k1 rejects it outright. A signer that emits high-S roughly half
  the time fails against those verifiers roughly half the time, which reads
  as flakiness rather than as a signature format problem.
- *Verifying* deliberately does **not** enforce low-S, because the ledger
  verifies through OpenSSL, which neither normalises nor requires it. Roughly
  half of all ledger-produced signatures are high-S, and rejecting them would
  be the same bug in the opposite direction.

Because signing is deterministic, this SDK's signatures are byte-identical to
`@noble/curves` for the same key and message — checked against published
reference bytes on every test run, not merely verified.

**Falcon signatures are not a fixed length.** They vary between roughly 649 and
662 bytes. Any buffer, column or assertion that assumes a constant size will
work for a while and then fail on a signature that happens to compress
differently.

**Falcon keys carry a one-byte header** — `0x09` on a public key, `0x59` on a
private key — which is why they are 897 and 1281 rather than 896 and 1280.
BouncyCastle strips it; this SDK adds it back, because the ledger stores the
headered form. A key that is 896 bytes has had its header removed somewhere,
and this SDK says so by name rather than reporting a generic length error.

**Signing is hedged**, not deterministic: fresh entropy goes into every
signature, so signing the same message twice produces different bytes. This
matches the reference implementation. Never compare signatures for equality —
verify them.

**The post-quantum schemes are hedged**, so signing the same message twice
produces different bytes. Never compare those for equality — verify them.
secp256k1 is the exception: it is deterministic, so it can be compared, and
this SDK does exactly that against the reference implementation.

Conformance is checked against the cross-language vectors published by the
ledger repository: all 24 verify — 6 per post-quantum scheme, and 12 for
secp256k1 covering both public key forms — and signatures produced here verify
against the reference public keys. The secp256k1 vectors additionally publish
the exact deterministic bytes a conforming signer must emit, and this SDK
reproduces all 12.

## Transactions

```csharp
var tx = Transaction.Builder()
    .Namespace("default")
    .Contract("mycontract")
    .Entry("transfer")                       // optional, omitted when unset
    .Input(streamId, signer, payload)        // repeat for multiple signers
    .Output(otherStream, payload)            // optional
    .ReadOnly("label", someStreamId)         // optional, see "Reading state"
    .Build();
```

Every signer signs the *same* bytes: the canonical form of `$tx`. `$sigs` is
keyed by input stream id.

Onboarding is different in two ways that catch every port, so it has its own
method:

```csharp
var tx = Transaction.Onboard(key);   // $selfsign: true, $sigs keyed by $i label
```

To inspect exactly what was signed — the fastest way to diagnose a rejected
signature:

```csharp
byte[] signed = tx.SignedBytes();
string json    = tx.ToJson();         // the full envelope, as submitted
```

## Reading state

There is no read API. A node's storage service listens only on that node's own
host, so reading state is a transaction like any other: name the streams in
`$r`, and the contract hands values back with `returnToRemote`.

```csharp
var tx = Transaction.Builder()
    .Namespace("default")
    .Contract("mycontract")
    .Entry("read")
    .Input(identity.StreamId, identity.Signer)
    .ReadOnly("target", streamToRead)
    .Build();

var response = await client.SubmitAsync(tx);

foreach (var value in response.Responses)
{
    Console.WriteLine(value.GetProperty("balance").GetInt32());
}
```

`response.NewStreams` gives the ids of any streams the transaction created.

## Events (SSE)

Event streams are served by **Activecore**, which is a separate service on its
own port — not a path on the node. Pointing a subscription at a node returns
403, so the URL is supplied separately and the SDK throws a message that says
which one is missing rather than quietly producing an empty stream.

```csharp
using var client = new ActiveledgerClient(
    "http://localhost:5260",
    coreUrl: "http://localhost:5261");

using var cts = new CancellationTokenSource();

// Every stream change on the ledger
await foreach (var e in client.SubscribeToActivityAsync(cancellationToken: cts.Token))
{
    Console.WriteLine(e.Data);
}

// Changes to one stream
await foreach (var e in client.SubscribeToActivityAsync(streamId, cts.Token)) { }

// Events a contract emitted: all, by contract, or one named event
await foreach (var e in client.SubscribeToContractEventsAsync()) { }
await foreach (var e in client.SubscribeToContractEventsAsync("mycontract")) { }
await foreach (var e in client.SubscribeToContractEventsAsync("mycontract", "transfer")) { }
```

**Activity and contract events are different feeds.** Activity fires for stream
changes, so it is what an ordinary transaction produces. Contract events carry
only what a contract explicitly emitted — subscribe there for a transaction
that emits nothing and you will correctly receive nothing, which looks exactly
like a broken subscription.

Each `LedgerEvent` has `Data`, and `Name` and `Id` when the server sent them.
Multiple `data:` lines join with newlines, and `:` heartbeat comments are
ignored rather than delivered as empty events.

Cancelling the token closes the connection. It really does close it: the token
passed to a request only covers sending it and reading the headers, so the SDK
also disposes the stream on cancellation. Without that, cancelling an idle
subscription would leave it blocked until the server next sent something.

`SubscribeAsync(pathOrUrl)` takes a raw path or an absolute URL, for endpoints
not covered above.

## Signing elsewhere

`ISigner` is all the SDK needs, so keys can live in an HSM, a remote signing
service or a user's wallet:

```csharp
public sealed class HsmSigner : ISigner
{
    public KeyType KeyType => KeyType.MlDsa65;
    public string PublicKey => /* ... */;
    public byte[] Sign(byte[] message) => /* ... */;
}
```

`Sign` receives the canonical bytes of `$tx` and returns a raw signature; the
SDK base64-encodes it.

## Things that will bite you

**A rejected transaction is an HTTP 200.** The ledger answers 200 and reports
the problem in the body. Check `response.Committed` — code that treats the HTTP
status as success will report commits that never happened, and will keep doing
so until something downstream notices the data is missing.

**Every signature problem is reported as 1220 "Signature Incorrect".** A wrong
key type, a missing `type`, wrong-length key material and genuinely bad bytes
all produce that one message. `tx.SignedBytes()` is usually the quickest way in.

**A missing `type` defaults to `rsa`.** The ledger then tries RSA verification
against whatever it was given. This SDK always sends the type explicitly.

**Namespaces are claimed permanently.** A test that registers a fixed namespace
passes once and fails every re-run against the same network, which reads like a
regression and is not one.

**Consensus is a majority.** When a submission returns, most nodes have
committed and the rest may still be writing. Reading immediately from a
specific node is a race.

## Canonical JSON

Signatures cover the exact bytes of `JSON.stringify($tx)` encoded as UTF-8 — no
hash prefix, no length prefix, no domain separator and **no key sorting**. A
signature over bytes that differ by a single escape is invalid.

`System.Text.Json` cannot produce these bytes: it escapes non-ASCII and
HTML-sensitive characters by default, and gives no insertion-order guarantee
for a dictionary. Both defects produce correct output for an ASCII-only payload
with one key, which is what makes them dangerous. So this SDK has its own
serialiser and its own insertion-ordered object:

```csharp
var payload = new JsonObject()
    .Set("zebra", 1)          // stays first - not sorted
    .Set("alpha", "text")
    .Set("nested", new JsonObject().Set("flag", true))
    .Set("list", new JsonArray().Add(1).Add("two"));

string json  = CanonicalJson.Stringify(payload);
byte[] bytes = CanonicalJson.Bytes(payload);
```

Numbers follow JavaScript: one numeric type, so `1.0` serialises as `1`. `NaN`
and infinity are refused rather than silently written as `null`. Formatting is
invariant-culture throughout, so a machine with a comma decimal separator does
not sign `1,5`.

## Testing

```bash
dotnet test
```

The live-network tests skip unless a ledger is configured. To run them, start a
network from an `activeledger` checkout:

```bash
npm run test:network:serve
```

then run with the URLs it prints:

```bash
AL_NODES=http://127.0.0.1:5510,http://127.0.0.1:5520 \
AL_STORAGE=http://127.0.0.1:5509,http://127.0.0.1:5519 \
dotnet test
```

They onboard real post-quantum identities, verify what the ledger actually
recorded, check that a tampered payload is rejected, and open a real event
stream.

## Migrating from 1.x

Version 2 is a rewrite. The old `ActiveLedgerLib` types are gone, along with
the vendored `BouncyCastle.Crypto.dll` and `Newtonsoft.Json.dll` — both are now
NuGet references, and JSON that gets signed goes through `CanonicalJson` rather
than `Newtonsoft.Json`, which cannot reproduce the required byte sequence.

| 1.x | 2.x |
|---|---|
| `GenerateKeyPair` | `KeyPair.Generate(KeyType)` |
| `GenerateTx` / `GenerateTxJson` | `Transaction.Builder()` |
| `GenerateSignature` | handled by `Build()` / `Transaction.Onboard()` |
| `MakeRequest` | `ActiveledgerClient` |
| `SDKPreferences` | constructor arguments |

### 2.0 to 2.1

`ISigner.PublicKeyBase64` is now `ISigner.PublicKey`, and `KeyPair`'s
`PublicKeyBase64` / `PrivateKeyBase64` are `PublicKey` / `PrivateKey`. The old
names described only the post-quantum encoding and would have been actively
wrong for secp256k1, which is hex.

## Licence

MIT
