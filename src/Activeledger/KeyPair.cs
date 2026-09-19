using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Activeledger
{
    /// <summary>
    /// A post-quantum key pair that interoperates with Activeledger.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Supports <c>ml-dsa-65</c> and <c>falcon-512</c>, both through
    /// BouncyCastle -- pure managed code, one dependency, no native binaries.
    /// Verified against the published cross-language vectors: all 12 pass.
    /// </para>
    /// <para>
    /// Keys are base64 of raw algorithm bytes, matching the JavaScript SDK's
    /// on-disk format.
    /// </para>
    /// </remarks>
    public sealed class KeyPair : ISigner
    {
        private const int FalconPublicBytes = 897;
        private const int FalconPrivateBytes = 1281;
        private const byte FalconPublicHeader = 0x09;
        private const byte FalconPrivateHeader = 0x59;
        private const int FalconF = 384;
        private const int FalconG = 384;

        private const int MlDsaPublicBytes = 1952;
        private const int MlDsaPrivateBytes = 4032;

        private readonly byte[] _public;
        private readonly byte[]? _private;

        private KeyPair(KeyType type, byte[] publicBytes, byte[]? privateBytes)
        {
            KeyType = type;
            _public = publicBytes;
            _private = privateBytes;
        }

        /// <summary>The algorithm this key pair uses.</summary>
        public KeyType KeyType { get; }

        /// <summary>
        /// The public key, exactly as the ledger stores it.
        /// </summary>
        /// <remarks>
        /// Base64 for the post-quantum schemes, 0x-prefixed hex for
        /// secp256k1. The encoding is not a detail a caller may choose: the
        /// ledger compares these strings, and a secp256k1 key written as
        /// base64 is rejected as 1220 "Signature Incorrect".
        /// </remarks>
        public string PublicKey => Encode(KeyType, _public);

        /// <summary>
        /// The private key, in the same encoding as <see cref="PublicKey"/>.
        /// Throws if this pair can only verify.
        /// </summary>
        public string PrivateKey =>
            _private is null
                ? throw new InvalidOperationException(
                    "This key pair has no private key - it was created for verification only")
                : Encode(KeyType, _private);

        /// <summary>Whether a private key is present.</summary>
        public bool CanSign => _private is not null;

        // -- construction ---------------------------------------------------

        /// <summary>
        /// Generates a fresh key pair, using the platform's secure random
        /// source.
        /// </summary>
        /// <param name="type">The scheme to generate.</param>
        /// <param name="compressed">
        /// secp256k1 only: emit the compressed 33-byte public key rather than
        /// the uncompressed 65-byte one. The ledger accepts both. Ignored by
        /// the post-quantum schemes.
        /// </param>
        public static KeyPair Generate(KeyType type, bool compressed = true)
        {
            var random = new SecureRandom();
            switch (type)
            {
                case KeyType.MlDsa65:
                {
                    var generator = new MLDsaKeyPairGenerator();
                    generator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
                    var pair = generator.GenerateKeyPair();
                    return new KeyPair(
                        type,
                        ((MLDsaPublicKeyParameters)pair.Public).GetEncoded(),
                        ((MLDsaPrivateKeyParameters)pair.Private).GetEncoded());
                }
                case KeyType.Falcon512:
                {
                    var generator = new FalconKeyPairGenerator();
                    generator.Init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));
                    var pair = generator.GenerateKeyPair();
                    // Header bytes added back here, once, so nothing
                    // downstream ever sees BouncyCastle's stripped form.
                    return new KeyPair(
                        type,
                        WithHeader(((FalconPublicKeyParameters)pair.Public).GetEncoded(), FalconPublicHeader),
                        WithHeader(((FalconPrivateKeyParameters)pair.Private).GetEncoded(), FalconPrivateHeader));
                }
                case KeyType.Secp256k1:
                {
                    var generator = new ECKeyPairGenerator("ECDSA");
                    generator.Init(new ECKeyGenerationParameters(Secp256k1Domain, random));
                    var pair = generator.GenerateKeyPair();

                    // Compressed by default: 33 bytes rather than 65, and this
                    // key is written into a transaction and then stored on an
                    // identity stream forever.
                    return new KeyPair(
                        type,
                        ((ECPublicKeyParameters)pair.Public).Q.GetEncoded(compressed),
                        Secp256k1Scalar(((ECPrivateKeyParameters)pair.Private).D));
                }
                default:
                    throw new NotSupportedException($"{type.ToWire()} key generation is not implemented");
            }
        }

        /// <summary>
        /// Derives a key pair from the algorithm's own seed.
        /// </summary>
        /// <remarks>
        /// <para>
        /// No key derivation function is applied: the bytes given are the
        /// seed the scheme itself takes - 32 for ml-dsa-65 and secp256k1, 48
        /// for falcon-512. A wrong length is refused rather than padded,
        /// because a padded seed is a different identity, not a malformed
        /// one.
        /// </para>
        /// <para>
        /// This is how a private key moves between Activeledger SDKs. The PHP
        /// SDK's ml-dsa-65 private key IS a 32-byte seed - its library
        /// implements FIPS 204 key generation from a seed but not
        /// skEncode/skDecode - so the 4032-byte encoding this SDK exports
        /// cannot be loaded there. The seed can be, and gives an identical
        /// public key.
        /// </para>
        /// <para>
        /// For secp256k1 the seed IS the private scalar, so it has to be a
        /// valid one. A scalar of zero, or one at or above the group order,
        /// is refused rather than reduced mod n: reducing produces a
        /// perfectly functional key belonging to a different identity, and
        /// nothing downstream ever reports a problem.
        /// </para>
        /// </remarks>
        /// <param name="type">The scheme to derive.</param>
        /// <param name="seed">The algorithm's seed, at its exact length.</param>
        /// <param name="compressed">Return a compressed public key (secp256k1 only).</param>
        public static KeyPair FromSeed(KeyType type, byte[] seed, bool compressed = true)
        {
            if (seed == null)
            {
                throw new ArgumentNullException(nameof(seed));
            }

            var expected = RecoveryPhrase.SeedSize(type);
            if (seed.Length != expected)
            {
                throw new ArgumentException(
                    $"{type.ToWire()} needs a {expected}-byte seed, got {seed.Length}. It is " +
                    "refused rather than padded: a padded seed is a different identity, not a " +
                    "malformed one.",
                    nameof(seed));
            }

            switch (type)
            {
                case KeyType.MlDsa65:
                {
                    // BouncyCastle's seed constructor, rather than driving the
                    // generator with a fixed SecureRandom. Both give the same
                    // key - measured - but this one says what it means.
                    var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
                    return new KeyPair(
                        type,
                        priv.GetPublicKey().GetEncoded(),
                        priv.GetEncoded());
                }
                case KeyType.Falcon512:
                {
                    // Falcon has no seed constructor, so the generator is fed
                    // a SecureRandom that yields exactly these bytes. Verified
                    // byte for byte against @noble/post-quantum across the
                    // full key.
                    var generator = new FalconKeyPairGenerator();
                    generator.Init(new FalconKeyGenerationParameters(
                        new FixedSecureRandom(seed), FalconParameters.falcon_512));
                    var pair = generator.GenerateKeyPair();

                    return new KeyPair(
                        type,
                        WithHeader(((FalconPublicKeyParameters)pair.Public).GetEncoded(), FalconPublicHeader),
                        WithHeader(((FalconPrivateKeyParameters)pair.Private).GetEncoded(), FalconPrivateHeader));
                }
                case KeyType.Secp256k1:
                {
                    var d = new BigInteger(1, seed);
                    if (d.SignValue == 0 || d.CompareTo(Secp256k1Domain.N) >= 0)
                    {
                        throw new ArgumentException(
                            "seed is not a valid secp256k1 private key - the scalar must be in " +
                            "[1, n-1]",
                            nameof(seed));
                    }

                    return new KeyPair(
                        type,
                        Secp256k1Domain.G.Multiply(d).Normalize().GetEncoded(compressed),
                        Secp256k1Scalar(d));
                }
                default:
                    throw new NotSupportedException(
                        $"{type.ToWire()} cannot be derived from a seed");
            }
        }

        /// <summary>
        /// Derives a key pair from a BIP-39 recovery phrase.
        /// </summary>
        /// <remarks>
        /// One phrase can back an ml-dsa-65, a falcon-512 and a secp256k1
        /// identity at once: each type derives its own seed, so none of them
        /// reveals the others.
        /// </remarks>
        /// <exception cref="ArgumentException">The phrase is not a valid mnemonic.</exception>
        public static KeyPair FromPhrase(
            KeyType type, string phrase, string passphrase = "", bool compressed = true)
        {
            var seed = RecoveryPhrase.DeriveSeed(type, RecoveryPhrase.ToSeed(phrase, passphrase));
            return FromSeed(type, seed, compressed);
        }

        /// <summary>
        /// Recovers a secp256k1 key pair from a phrase made by
        /// <c>@activeledger/sdk-bip39</c>.
        /// </summary>
        /// <remarks>
        /// That scheme is SHA256(phrase) used directly as the scalar - no key
        /// stretching, no domain separation, no passphrase. It exists so an
        /// old phrase can be recovered, never so a new key can be made with
        /// it.
        ///
        /// Deliberately does NOT validate the mnemonic: the original package
        /// hashed the string as given and never consulted the wordlist, so
        /// rejecting a phrase here that it accepted would make a recoverable
        /// identity unrecoverable.
        /// </remarks>
        public static KeyPair FromLegacyPhrase(string phrase, bool compressed = true)
        {
            if (phrase == null)
            {
                throw new ArgumentNullException(nameof(phrase));
            }

            return FromSeed(
                KeyType.Secp256k1, Sha256(Encoding.UTF8.GetBytes(phrase)), compressed);
        }

        /// <summary>
        /// A SecureRandom that yields fixed bytes, so keygen is deterministic.
        /// </summary>
        /// <remarks>
        /// Only for Falcon, which BouncyCastle offers no seed constructor
        /// for. It cycles the seed rather than running out, because the
        /// generator may ask for more bytes than the seed holds.
        /// </remarks>
        private sealed class FixedSecureRandom : SecureRandom
        {
            private readonly byte[] _seed;
            private int _position;

            internal FixedSecureRandom(byte[] seed) => _seed = seed;

            public override void NextBytes(byte[] buffer)
            {
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i] = _seed[_position++ % _seed.Length];
                }
            }
        }

        /// <summary>A verify-only key pair.</summary>
        /// <param name="type">The scheme the key belongs to.</param>
        /// <param name="publicKey">
        /// The key exactly as the ledger stores it: base64 for the
        /// post-quantum schemes, 0x-prefixed hex for secp256k1.
        /// </param>
        public static KeyPair FromPublic(KeyType type, string publicKey)
        {
            var publicBytes = Decode(type, publicKey, "public");
            CheckPublicLength(type, publicBytes);
            return new KeyPair(type, publicBytes, null);
        }

        /// <summary>
        /// A signing key pair.
        /// </summary>
        /// <remarks>
        /// Takes both halves because BouncyCastle cannot construct a Falcon
        /// private key without a public key, and the ledger's private key does
        /// not contain one. The SDK's own key file carries both, so this costs
        /// a caller nothing.
        /// </remarks>
        public static KeyPair FromKeys(KeyType type, string publicKey, string privateKey)
        {
            var publicBytes = Decode(type, publicKey, "public");
            var privateBytes = Decode(type, privateKey, "private");
            CheckPublicLength(type, publicBytes);
            CheckLength(type, privateBytes, PrivateSize(type), "private");
            return new KeyPair(type, publicBytes, privateBytes);
        }

        // -- signing --------------------------------------------------------

        /// <summary>
        /// Signs a message, returning the raw signature.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Whether the result is reproducible depends on the scheme, and the
        /// two cases are opposite.
        /// </para>
        /// <para>
        /// <b>The post-quantum schemes are HEDGED.</b> Fresh entropy goes into
        /// every call, so signing the same message twice gives different
        /// bytes. That matches the reference implementation, and it means such
        /// a signature can never be compared for equality -- only verified.
        /// </para>
        /// <para>
        /// <b>secp256k1 is DETERMINISTIC</b> (RFC 6979) and always low-S, so
        /// the same key and message give the same bytes in every correct
        /// implementation. That is deliberate: it is what allows an exact
        /// comparison against published reference bytes, which is the only
        /// kind of test that can catch a low-S regression. Compare those
        /// freely.
        /// </para>
        /// </remarks>
        public byte[] Sign(byte[] message)
        {
            if (_private is null)
            {
                throw new InvalidOperationException(
                    "This key pair has no private key - it was created for verification only");
            }

            switch (KeyType)
            {
                case KeyType.MlDsa65:
                {
                    var key = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, _private);
                    var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                    // ParametersWithRandom selects the hedged variant, matching
                    // the reference implementation. A bare key would give
                    // rnd = 0^32 and be deterministic - valid FIPS 204, but a
                    // different posture, and not one to adopt by accident.
                    signer.Init(true, new ParametersWithRandom(key, new SecureRandom()));
                    signer.BlockUpdate(message, 0, message.Length);
                    return signer.GenerateSignature();
                }
                case KeyType.Falcon512:
                {
                    var body = WithoutHeader(_private, FalconPrivateHeader, FalconPrivateBytes, "private");
                    var h = WithoutHeader(_public, FalconPublicHeader, FalconPublicBytes, "public");
                    var f = Slice(body, 0, FalconF);
                    var g = Slice(body, FalconF, FalconG);
                    var bigF = Slice(body, FalconF + FalconG, body.Length - FalconF - FalconG);

                    var signer = new FalconSigner();
                    signer.Init(true, new FalconPrivateKeyParameters(FalconParameters.falcon_512, f, g, bigF, h));
                    return signer.GenerateSignature(message);
                }
                case KeyType.Secp256k1:
                {
                    // Deterministic (RFC 6979) and low-S. Both are choices,
                    // and both are explained where they are made below.
                    var key = new ECPrivateKeyParameters(new BigInteger(1, _private), Secp256k1Domain);
                    var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
                    signer.Init(true, key);

                    var components = signer.GenerateSignature(Sha256(message));
                    return EncodeDer(components[0], LowS(components[1]));
                }
                default:
                    throw new NotSupportedException($"{KeyType.ToWire()} signing is not implemented");
            }
        }

        /// <summary>
        /// Verifies a signature.
        /// </summary>
        /// <remarks>
        /// Returns false rather than throwing for malformed input. A caller
        /// should not have to distinguish "this signature is invalid" from
        /// "this signature is the wrong shape" -- both mean the same thing at
        /// the call site, and making one an exception invites a catch that
        /// swallows the other.
        /// </remarks>
        public bool Verify(byte[] message, byte[] signature)
        {
            try
            {
                switch (KeyType)
                {
                    case KeyType.MlDsa65:
                    {
                        var key = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, _public);
                        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
                        verifier.Init(false, key);
                        verifier.BlockUpdate(message, 0, message.Length);
                        return verifier.VerifySignature(signature);
                    }
                    case KeyType.Falcon512:
                    {
                        var h = WithoutHeader(_public, FalconPublicHeader, FalconPublicBytes, "public");
                        var verifier = new FalconSigner();
                        verifier.Init(false, new FalconPublicKeyParameters(FalconParameters.falcon_512, h));
                        return verifier.VerifySignature(message, signature);
                    }
                    case KeyType.Secp256k1:
                    {
                        var point = Secp256k1Domain.Curve.DecodePoint(_public);
                        var key = new ECPublicKeyParameters(point, Secp256k1Domain);
                        var verifier = new ECDsaSigner();
                        verifier.Init(false, key);

                        var (r, sig) = DecodeDer(signature);

                        // Deliberately accepting HIGH-S as well as low.
                        //
                        // This SDK only ever emits low-S, but it must verify
                        // what others produce, and the ledger verifies through
                        // OpenSSL, which neither normalises nor requires it.
                        // Rejecting high-S here would reject signatures the
                        // ledger itself made - roughly half of them - which
                        // presents as intermittent rather than as a format
                        // problem. @noble/curves and libsecp256k1 both reject
                        // by default; this is the opposite choice, on purpose.
                        return verifier.VerifySignature(Sha256(message), r, sig);
                    }
                    default:
                        throw new NotSupportedException($"{KeyType.ToWire()} verification is not implemented");
                }
            }
            catch (NotSupportedException)
            {
                throw;
            }
            catch
            {
                return false;
            }
        }

        // -- helpers --------------------------------------------------------

        /// <summary>
        /// secp256k1's domain parameters, built once.
        /// </summary>
        private static readonly ECDomainParameters Secp256k1Domain = BuildSecp256k1Domain();

        private static ECDomainParameters BuildSecp256k1Domain()
        {
            var curve = SecNamedCurves.GetByName("secp256k1");
            return new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        }

        /// <summary>
        /// The private scalar as a fixed 32 bytes.
        /// </summary>
        /// <remarks>
        /// Left-padded deliberately. A BigInteger drops leading zero bytes,
        /// which happens to roughly 1 key in 400, and the shorter string is a
        /// different scalar to anything that reads it strictly. The reference
        /// SDK pads for exactly this reason.
        /// </remarks>
        private static byte[] Secp256k1Scalar(BigInteger d) =>
            BigIntegers.AsUnsignedByteArray(32, d);

        private static byte[] Sha256(byte[] message)
        {
            var digest = new Sha256Digest();
            var hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(message, 0, message.Length);
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Folds S into the lower half of the curve order.
        /// </summary>
        /// <remarks>
        /// <para>
        /// (r, s) and (r, n - s) are both valid signatures over the same
        /// message - ECDSA malleability. The ledger accepts either, so this is
        /// not required for the ledger's sake.
        /// </para>
        /// <para>
        /// It is required for everything else. @noble/curves rejects high-S
        /// unless explicitly told not to, and it is the reference for the
        /// JavaScript side; libsecp256k1 rejects it outright. A signer that
        /// emits high-S roughly half the time therefore fails against those
        /// verifiers roughly half the time, which reads as flakiness rather
        /// than as a signature format problem. Emitting only low-S costs one
        /// subtraction and makes this SDK agree with all of them.
        /// </para>
        /// </remarks>
        private static BigInteger LowS(BigInteger s)
        {
            var halfOrder = Secp256k1Domain.N.ShiftRight(1);
            return s.CompareTo(halfOrder) > 0 ? Secp256k1Domain.N.Subtract(s) : s;
        }

        /// <summary>
        /// DER-encodes the signature components.
        /// </summary>
        /// <remarks>
        /// DER is what the ledger base64s into <c>$sigs</c>. Its length varies
        /// with the size of r and s, so nothing may treat it as fixed, and a
        /// raw 64-byte r||s pair is not a substitute.
        /// </remarks>
        private static byte[] EncodeDer(BigInteger r, BigInteger s) =>
            new DerSequence(new DerInteger(r), new DerInteger(s)).GetEncoded("DER");

        private static (BigInteger R, BigInteger S) DecodeDer(byte[] signature)
        {
            var sequence = (Asn1Sequence)Asn1Object.FromByteArray(signature);
            if (sequence.Count != 2)
            {
                throw new ArgumentException($"DER signature has {sequence.Count} components, expected 2");
            }

            return (
                ((DerInteger)sequence[0]).PositiveValue,
                ((DerInteger)sequence[1]).PositiveValue);
        }

        /// <summary>Encodes key bytes the way the ledger stores them.</summary>
        private static string Encode(KeyType type, byte[] bytes) =>
            type == KeyType.Secp256k1
                ? "0x" + Hex.ToHexString(bytes)
                : Convert.ToBase64String(bytes);

        /// <summary>
        /// Checks a public key's length.
        /// </summary>
        /// <remarks>
        /// Separate from the private check because secp256k1 has two valid
        /// public key lengths: 33 compressed and 65 uncompressed. The ledger
        /// accepts either, so this SDK must too.
        /// </remarks>
        private static void CheckPublicLength(KeyType type, byte[] bytes)
        {
            if (type != KeyType.Secp256k1)
            {
                CheckLength(type, bytes, PublicSize(type), "public");
                return;
            }

            if (bytes.Length is not (33 or 65))
            {
                throw new ArgumentException(
                    $"secp256k1 public key is {bytes.Length} bytes, expected 33 (compressed) " +
                    "or 65 (uncompressed)");
            }

            var prefix = bytes[0];
            var ok = bytes.Length == 33 ? prefix is 0x02 or 0x03 : prefix == 0x04;
            if (!ok)
            {
                throw new ArgumentException(
                    $"secp256k1 public key starts with 0x{prefix:x2}, which does not match its " +
                    $"length of {bytes.Length} bytes (expected 0x02/0x03 for 33, 0x04 for 65)");
            }
        }

        private static int PublicSize(KeyType type) => type switch
        {
            KeyType.MlDsa65 => MlDsaPublicBytes,
            KeyType.Falcon512 => FalconPublicBytes,
            _ => 0,
        };

        private static int PrivateSize(KeyType type) => type switch
        {
            KeyType.MlDsa65 => MlDsaPrivateBytes,
            KeyType.Falcon512 => FalconPrivateBytes,
            _ => 0,
        };

        /// <summary>
        /// Decodes key material in whichever encoding the scheme uses.
        /// </summary>
        /// <remarks>
        /// The two encodings are not interchangeable and a mix-up is quiet:
        /// most base64 strings are not valid hex and fail loudly here, but a
        /// hex string with no 0x prefix can decode as base64 into plausible
        /// bytes of the wrong length, which is why the prefix is required
        /// rather than tolerated.
        /// </remarks>
        private static byte[] Decode(KeyType type, string value, string what)
        {
            // Checked explicitly so null reports what it is. Everything else
            // on this path explains itself -- the empty-string case spells out
            // why the 0x prefix is required -- and null is the likeliest bad
            // value to arrive, since it comes from configuration or a database
            // column rather than from a typo.
            if (value is null)
            {
                throw new ArgumentNullException(
                    nameof(value), $"{type.ToWire()} {what} key was null");
            }

            if (type != KeyType.Secp256k1)
            {
                try
                {
                    return Convert.FromBase64String(value);
                }
                catch (FormatException e)
                {
                    throw new ArgumentException($"{what} key is not valid base64", e);
                }
            }

            if (!value.StartsWith("0x", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"secp256k1 {what} key must start with '0x' - that prefix is part of what " +
                    "the ledger stores, not decoration. Post-quantum keys are base64; these are not.");
            }

            var body = value.Substring(2);
            if (body.Length % 2 != 0)
            {
                throw new ArgumentException(
                    $"secp256k1 {what} key has an odd number of hex digits ({body.Length})");
            }

            try
            {
                return Hex.Decode(body);
            }
            catch (Exception e)
            {
                throw new ArgumentException($"secp256k1 {what} key is not valid hex", e);
            }
        }

        private static void CheckLength(KeyType type, byte[] bytes, int expected, string what)
        {
            if (expected == 0) return;
            if (bytes.Length != expected)
            {
                // Caught here rather than at a node. A wrong-length key reaching
                // the ledger comes back as 1220 "Signature Incorrect", which
                // says nothing about length and sends the caller hunting the
                // signer.
                var hint = bytes.Length == expected - 1
                    ? " - this looks like a BouncyCastle key with its header byte stripped"
                    : string.Empty;
                throw new ArgumentException(
                    $"{type.ToWire()} {what} key should be {expected} bytes, got {bytes.Length}{hint}");
            }
        }

        /// <summary>
        /// BouncyCastle's raw Falcon getters omit the 1-byte type header: a
        /// public key comes back 896 bytes rather than 897, a private key 1280
        /// rather than 1281. Same bit packing, header stripped by the decoder.
        /// A port that never adds it back produces keys the ledger rejects, and
        /// the failure presents as a signature problem rather than a key one.
        /// </summary>
        private static byte[] WithHeader(byte[] body, byte header)
        {
            var result = new byte[body.Length + 1];
            result[0] = header;
            Buffer.BlockCopy(body, 0, result, 1, body.Length);
            return result;
        }

        private static byte[] WithoutHeader(byte[] bytes, byte header, int expected, string what)
        {
            if (bytes.Length != expected)
            {
                throw new ArgumentException(
                    $"falcon-512 {what} key should be {expected} bytes, got {bytes.Length}");
            }
            if (bytes[0] != header)
            {
                throw new ArgumentException(
                    $"falcon-512 {what} key should start with 0x{header:x2}, got 0x{bytes[0]:x2}");
            }
            return Slice(bytes, 1, bytes.Length - 1);
        }

        private static byte[] Slice(byte[] source, int offset, int length)
        {
            var result = new byte[length];
            Buffer.BlockCopy(source, offset, result, 0, length);
            return result;
        }

        /// <summary>A description that never includes private key material.</summary>
        public override string ToString() =>
            $"KeyPair({KeyType.ToWire()}, {(CanSign ? "public+private" : "public only")})";
    }
}
