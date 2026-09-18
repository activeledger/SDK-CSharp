[![Activeledger](https://www.activeledger.io/wp-content/uploads/2018/09/Asset-1.png)](https://activeledger.io/)

# Activeledger SDK for C#

Build, sign and submit Activeledger transactions from .NET, with support for
post-quantum identities.

- **ML-DSA-65** and **Falcon-512** alongside the classical key types
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

## Post-quantum support

Both schemes the ledger accepts are supported, and either can hold an identity.

| Key type | Wire string | Public | Private | Signature |
|---|---|---|---|---|
| `KeyType.MlDsa65` | `ml-dsa-65` | 1952 | 4032 | 3309 |
| `KeyType.Falcon512` | `falcon-512` | 897 | 1281 | **649–662, variable** |
| `KeyType.Rsa` | `rsa` | — | — | — |
| `KeyType.Secp256k1` | `secp256k1` | — | — | — |

```csharp
var mldsa  = KeyPair.Generate(KeyType.MlDsa65);
var falcon = KeyPair.Generate(KeyType.Falcon512);

// Base64, in exactly the encoding the ledger stores
string pub  = mldsa.PublicKeyBase64;
string priv = mldsa.PrivateKeyBase64;

// Round-trip a stored key
var restored = KeyPair.FromKeys(KeyType.MlDsa65, pub, priv);

// Verification only - no private key, and Sign() throws
var verifier = KeyPair.FromPublic(KeyType.MlDsa65, pub);
```

Three things about these keys are worth knowing before they cost you an
afternoon.

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

Conformance is checked against the cross-language vectors published by the
ledger repository: all 12 (6 per scheme) verify, and signatures produced here
verify against the reference public keys.

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
    public string PublicKeyBase64 => /* ... */;
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

## Licence

MIT
