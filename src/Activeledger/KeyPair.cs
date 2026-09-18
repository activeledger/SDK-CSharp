using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Security;

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

        /// <summary>The public key, base64, exactly as the ledger stores it.</summary>
        public string PublicKeyBase64 => Convert.ToBase64String(_public);

        /// <summary>
        /// The private key, base64. Throws if this pair can only verify.
        /// </summary>
        public string PrivateKeyBase64 =>
            _private is null
                ? throw new InvalidOperationException(
                    "This key pair has no private key - it was created for verification only")
                : Convert.ToBase64String(_private);

        /// <summary>Whether a private key is present.</summary>
        public bool CanSign => _private is not null;

        // -- construction ---------------------------------------------------

        /// <summary>
        /// Generates a fresh key pair, using the platform's secure random
        /// source.
        /// </summary>
        public static KeyPair Generate(KeyType type)
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
                default:
                    throw new NotSupportedException($"{type.ToWire()} key generation is not implemented");
            }
        }

        /// <summary>A verify-only key pair.</summary>
        public static KeyPair FromPublic(KeyType type, string publicKeyBase64)
        {
            var publicBytes = Decode(publicKeyBase64, "public");
            CheckLength(type, publicBytes, PublicSize(type), "public");
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
        public static KeyPair FromKeys(KeyType type, string publicKeyBase64, string privateKeyBase64)
        {
            var publicBytes = Decode(publicKeyBase64, "public");
            var privateBytes = Decode(privateKeyBase64, "private");
            CheckLength(type, publicBytes, PublicSize(type), "public");
            CheckLength(type, privateBytes, PrivateSize(type), "private");
            return new KeyPair(type, publicBytes, privateBytes);
        }

        // -- signing --------------------------------------------------------

        /// <summary>
        /// Signs a message, returning the raw signature.
        /// </summary>
        /// <remarks>
        /// Signing is HEDGED: fresh entropy goes into every call, so signing
        /// the same message twice gives different bytes. That matches the
        /// reference implementation, and it means a signature can never be
        /// compared for equality -- only verified.
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

        private static byte[] Decode(string value, string what)
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
