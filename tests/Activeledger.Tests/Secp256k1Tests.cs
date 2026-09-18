using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// secp256k1 conformance against the published cross-language vectors.
    ///
    /// Its encoding has nothing in common with the post-quantum schemes, and
    /// every test here exists because reusing the base64 path produces
    /// material the ledger rejects as 1220 "Signature Incorrect" while saying
    /// nothing else.
    /// </summary>
    public class Secp256k1Tests
    {
        private sealed record Vector(
            string Name, string Form, byte[] Message,
            string PublicKey, string PrivateKey, byte[] Signature,
            string DeterministicSignature);

        private static readonly List<Vector> Vectors = Load();

        private static List<Vector> Load()
        {
            var raw = File.ReadAllText(Path.Combine("testdata", "pq-vectors.json"));
            using var doc = JsonDocument.Parse(raw);
            var result = new List<Vector>();

            foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
            {
                if (v.GetProperty("type").GetString() != "secp256k1") continue;

                result.Add(new Vector(
                    v.GetProperty("messageName").GetString()!,
                    v.GetProperty("publicKeyForm").GetString()!,
                    new UTF8Encoding(false).GetBytes(v.GetProperty("message").GetString()!),
                    v.GetProperty("publicKey").GetString()!,
                    v.GetProperty("privateKey").GetString()!,
                    Convert.FromBase64String(v.GetProperty("signature").GetString()!),
                    v.GetProperty("deterministicSignature").GetString()!));
            }

            return result;
        }

        /// <summary>
        /// The ledger accepts both public key forms, so a port that only ever
        /// sees one never learns to read the other.
        /// </summary>
        [Fact]
        public void BothPublicKeyFormsArePresentInTheVectors()
        {
            Assert.Contains(Vectors, v => v.Form == "compressed");
            Assert.Contains(Vectors, v => v.Form == "uncompressed");
            Assert.True(Vectors.Count >= 12, $"expected at least 12, found {Vectors.Count}");
        }

        [Fact]
        public void VerifiesEveryPublishedSignature()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromPublic(KeyType.Secp256k1, v.PublicKey);
                Assert.True(key.Verify(v.Message, v.Signature),
                    $"failed to verify published secp256k1/{v.Name}/{v.Form}");
            }
        }

        [Fact]
        public void SignaturesMadeHereVerifyWithTheReferencePublicKey()
        {
            foreach (var v in Vectors)
            {
                var signer = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);
                var mine = signer.Sign(v.Message);

                var verifier = KeyPair.FromPublic(KeyType.Secp256k1, v.PublicKey);
                Assert.True(verifier.Verify(v.Message, mine),
                    $"reference key rejected a signature made here ({v.Name}/{v.Form})");
            }
        }

        [Fact]
        public void RoundTripsPublishedKeysExactly()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);
                Assert.Equal(v.PublicKey, key.PublicKey);
                Assert.Equal(v.PrivateKey, key.PrivateKey);
            }
        }

        [Fact]
        public void TamperedMessageDoesNotVerify()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromPublic(KeyType.Secp256k1, v.PublicKey);
                var tampered = v.Message.Concat(new byte[] { (byte)' ' }).ToArray();
                Assert.False(key.Verify(tampered, v.Signature));
            }
        }

        /// <summary>secp256k1's group order, and the low/high S boundary.</summary>
        private static readonly System.Numerics.BigInteger N =
            System.Numerics.BigInteger.Parse(
                "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                System.Globalization.NumberStyles.HexNumber);

        private static System.Numerics.BigInteger HalfN => N / 2;

        /// <summary>Pulls S out of a DER signature.</summary>
        private static System.Numerics.BigInteger SignatureS(byte[] der)
        {
            var i = 2;
            i += 2 + der[i + 1];                       // skip R
            var length = der[i + 1];
            var bytes = der.Skip(i + 2).Take(length).Reverse().Concat(new byte[] { 0 }).ToArray();
            return new System.Numerics.BigInteger(bytes);
        }

        private static bool IsHighS(byte[] der) => SignatureS(der) > HalfN;

        /// <summary>
        /// Signing is deterministic (RFC 6979), unlike the post-quantum
        /// schemes.
        /// </summary>
        /// <remarks>
        /// ECDSA has no reason to be hedged the way ML-DSA is, and a
        /// deterministic signer can be checked far more strictly: the same
        /// key and message must give the same bytes in every correct
        /// implementation, so exact signature bytes can be published as
        /// cross-language vectors. A random k reduces every test to "is this
        /// a valid signature", which cannot catch a low-S regression at all.
        /// </remarks>
        [Fact]
        public void SigningIsDeterministic()
        {
            var v = Vectors[0];
            var key = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);

            var first = key.Sign(v.Message);
            var second = key.Sign(v.Message);

            Assert.Equal(first, second);
            Assert.True(key.Verify(v.Message, first));
        }

        [Fact]
        public void DifferentMessagesStillProduceDifferentSignatures()
        {
            var v = Vectors[0];
            var key = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);

            Assert.NotEqual(key.Sign(v.Message), key.Sign(Vectors[1].Message));
        }

        /// <summary>
        /// Every signature this SDK emits is low-S.
        /// </summary>
        /// <remarks>
        /// Not for the ledger's benefit -- it accepts either. For everything
        /// else: @noble/curves rejects high-S unless told otherwise and is the
        /// reference for the JavaScript side, and libsecp256k1 rejects it
        /// outright. Emitting high-S roughly half the time fails against those
        /// verifiers roughly half the time, which reads as flaky rather than
        /// as a format problem.
        /// </remarks>
        [Fact]
        public void EverySignatureEmittedIsLowS()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);

            for (var i = 0; i < 200; i++)
            {
                var signature = key.Sign(new UTF8Encoding(false).GetBytes($"message {i}"));
                Assert.False(IsHighS(signature), $"signature {i} was high-S");
            }
        }

        /// <summary>
        /// High-S signatures must still VERIFY.
        /// </summary>
        /// <remarks>
        /// The other half of the rule, and the half that is easy to get wrong
        /// by adopting a library default. The ledger verifies through OpenSSL,
        /// which neither normalises nor requires low-S, so it produces high-S
        /// signatures freely. Seven of the published vectors are high-S; a
        /// verifier that enforced low-S would reject every one of them.
        /// </remarks>
        [Fact]
        public void HighSSignaturesFromElsewhereStillVerify()
        {
            var highS = Vectors.Where(v => IsHighS(v.Signature)).ToList();

            Assert.True(highS.Count > 0,
                "the published vectors no longer contain a high-S signature, so this test proves nothing");

            foreach (var v in highS)
            {
                var key = KeyPair.FromPublic(KeyType.Secp256k1, v.PublicKey);
                Assert.True(key.Verify(v.Message, v.Signature),
                    $"rejected a high-S signature ({v.Name}/{v.Form}) - low-S is being enforced on verify");
            }
        }

        /// <summary>
        /// DER length varies with the size of r and s. Anything that assumes a
        /// fixed size works until it doesn't.
        /// </summary>
        [Fact]
        public void SignatureIsDerAndItsLengthVaries()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var lengths = new HashSet<int>();

            for (var i = 0; i < 200; i++)
            {
                var signature = key.Sign(new UTF8Encoding(false).GetBytes($"message {i}"));

                // A DER SEQUENCE whose length header matches its body. A raw
                // r||s pair would be a fixed 64 bytes and rejected by the
                // ledger with nothing but 1220 to go on.
                Assert.Equal(0x30, signature[0]);
                Assert.Equal(signature.Length - 2, signature[1]);
                Assert.InRange(signature.Length, 64, 72);

                lengths.Add(signature.Length);
            }

            Assert.True(lengths.Count > 1,
                $"200 signatures all had length {lengths.First()} - DER should vary");
        }

        [Fact]
        public void GeneratedKeysUseTheLedgersEncoding()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);

            Assert.StartsWith("0x", key.PublicKey);
            Assert.StartsWith("0x", key.PrivateKey);

            // Compressed by default: 33 bytes, so "0x" + 66 hex characters.
            Assert.Equal(68, key.PublicKey.Length);
            Assert.Equal(66, key.PrivateKey.Length);
            Assert.Contains(key.PublicKey.Substring(2, 2), new[] { "02", "03" });
        }

        [Fact]
        public void UncompressedGenerationIsAvailable()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1, compressed: false);

            Assert.Equal(132, key.PublicKey.Length);
            Assert.StartsWith("0x04", key.PublicKey);
            Assert.True(key.Verify(new byte[] { 1 }, key.Sign(new byte[] { 1 })));
        }

        /// <summary>
        /// The private scalar must be left-padded to 32 bytes.
        /// </summary>
        /// <remarks>
        /// A BigInteger drops leading zero bytes, which happens to roughly one
        /// key in 400. The shorter string is a different scalar to anything
        /// reading it strictly, so this generates enough keys to be likely to
        /// hit one and asserts the length never moves.
        /// </remarks>
        [Fact]
        public void PrivateKeysAreAlwaysLeftPaddedTo32Bytes()
        {
            for (var i = 0; i < 1500; i++)
            {
                var key = KeyPair.Generate(KeyType.Secp256k1);
                Assert.Equal(66, key.PrivateKey.Length);
            }
        }

        /// <summary>
        /// A key with a leading zero byte must survive a round trip.
        /// </summary>
        [Fact]
        public void AScalarWithLeadingZeroBytesRoundTrips()
        {
            // Deliberately constructed rather than hunted for.
            var scalar = new byte[32];
            scalar[0] = 0x00;
            scalar[1] = 0x00;
            scalar[31] = 0x2a;
            var hex = "0x" + BitConverter.ToString(scalar).Replace("-", "").ToLowerInvariant();

            var generated = KeyPair.Generate(KeyType.Secp256k1);
            var restored = KeyPair.FromKeys(KeyType.Secp256k1, generated.PublicKey, hex);

            Assert.Equal(hex, restored.PrivateKey);
            Assert.Equal(66, restored.PrivateKey.Length);
        }

        [Fact]
        public void FreshlyGeneratedKeysVerifyTheirOwnSignatures()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var message = new UTF8Encoding(false).GetBytes("round trip");

            Assert.True(key.Verify(message, key.Sign(message)));
        }

        /// <summary>
        /// The prefix is part of what the ledger stores, not decoration.
        /// Tolerating its absence would let a caller store a key the ledger
        /// cannot read.
        /// </summary>
        [Fact]
        public void AKeyWithoutTheHexPrefixIsRefusedWithAnExplanation()
        {
            var valid = KeyPair.Generate(KeyType.Secp256k1).PublicKey;
            var stripped = valid.Substring(2);

            var error = Assert.Throws<ArgumentException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, stripped));

            Assert.Contains("0x", error.Message);
        }

        [Fact]
        public void WrongLengthPublicKeyIsRejectedWithBothValidLengths()
        {
            var error = Assert.Throws<ArgumentException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, "0x" + new string('a', 40)));

            Assert.Contains("33", error.Message);
            Assert.Contains("65", error.Message);
        }

        /// <summary>
        /// A length and a point prefix that disagree means the caller has
        /// mixed up the two forms somewhere.
        /// </summary>
        [Fact]
        public void APrefixThatContradictsTheLengthIsRejected()
        {
            // 33 bytes but claiming to be uncompressed.
            var bogus = "0x04" + new string('a', 64);

            var error = Assert.Throws<ArgumentException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, bogus));

            Assert.Contains("0x04", error.Message);
        }

        /// <summary>
        /// A null key must report what it is.
        /// </summary>
        /// <remarks>
        /// It used to fall through to a raw NullReferenceException while every
        /// other error on this path explained itself. Null is also the
        /// likeliest bad value to arrive, because it comes from configuration
        /// or a database column rather than from a typo.
        /// </remarks>
        [Fact]
        public void ANullKeyIsReportedAsNullRatherThanDereferenced()
        {
            var valid = KeyPair.Generate(KeyType.Secp256k1);

            Assert.Throws<ArgumentNullException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, null!));
            Assert.Throws<ArgumentNullException>(
                () => KeyPair.FromKeys(KeyType.Secp256k1, valid.PublicKey, null!));
            Assert.Throws<ArgumentNullException>(
                () => KeyPair.FromKeys(KeyType.Secp256k1, null!, valid.PrivateKey));

            // The post-quantum path too, which shares the same decoder.
            Assert.Throws<ArgumentNullException>(
                () => KeyPair.FromPublic(KeyType.MlDsa65, null!));
        }

        [Fact]
        public void NonHexIsRejected()
        {
            Assert.Throws<ArgumentException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, "0xzzzz"));
        }

        [Fact]
        public void VerifyOnlyKeyPairRefusesToSign()
        {
            var key = KeyPair.FromPublic(KeyType.Secp256k1, Vectors[0].PublicKey);

            Assert.False(key.CanSign);
            Assert.Throws<InvalidOperationException>(() => key.Sign(new byte[] { 1 }));
            Assert.Throws<InvalidOperationException>(() => key.PrivateKey);
        }

        [Fact]
        public void MalformedSignatureReturnsFalseRatherThanThrowing()
        {
            var v = Vectors[0];
            var key = KeyPair.FromPublic(KeyType.Secp256k1, v.PublicKey);

            Assert.False(key.Verify(v.Message, Array.Empty<byte>()));
            Assert.False(key.Verify(v.Message, new byte[10]));
            Assert.False(key.Verify(v.Message, new byte[64]));   // raw r||s, not DER
        }

        /// <summary>
        /// The ledger routes `bitcoin` and `ethereum` to identical secp256k1
        /// verification, so an existing identity may carry either. They parse,
        /// and they are never written back.
        /// </summary>
        [Fact]
        public void BitcoinAndEthereumParseAsSecp256k1ButAreNeverEmitted()
        {
            Assert.Equal(KeyType.Secp256k1, KeyTypes.FromWire("bitcoin"));
            Assert.Equal(KeyType.Secp256k1, KeyTypes.FromWire("ethereum"));

            Assert.Equal("secp256k1", KeyTypes.FromWire("bitcoin").ToWire());
            Assert.Equal("secp256k1", KeyTypes.FromWire("ethereum").ToWire());
        }

        /// <summary>
        /// The strongest test in this file: the exact bytes, not just a valid
        /// signature.
        /// </summary>
        /// <remarks>
        /// These expected values come from @noble/curves via sdk-web, an
        /// entirely separate implementation. Agreeing with them byte for byte
        /// means agreeing on RFC 6979's k, on low-S normalisation and on DER
        /// encoding all at once -- none of which a verify-round-trip test can
        /// see. This is only possible because ECDSA signing is deterministic;
        /// the post-quantum schemes are hedged and can never be checked this
        /// way.
        /// </remarks>
        [Fact]
        public void SignaturesAreByteIdenticalToTheReferenceImplementation()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);
                var mine = Convert.ToBase64String(key.Sign(v.Message));

                Assert.True(mine == v.DeterministicSignature,
                    $"{v.Name}/{v.Form}: signature differs from the reference.\n" +
                    $"  expected {v.DeterministicSignature}\n" +
                    $"  got      {mine}\n" +
                    "  If r matches and only s differs, low-S normalisation is the cause.");
            }
        }

        /// <summary>
        /// The published deterministic signatures must themselves be low-S,
        /// or the test above would be enforcing the wrong thing.
        /// </summary>
        [Fact]
        public void TheReferenceSignaturesAreLowS()
        {
            foreach (var v in Vectors)
            {
                Assert.False(IsHighS(Convert.FromBase64String(v.DeterministicSignature)),
                    $"{v.Name}/{v.Form}: the published reference signature is high-S");
            }
        }

        /// <summary>
        /// The size argument for supporting it at all, asserted so it cannot
        /// quietly stop being true.
        /// </summary>
        [Fact]
        public void KeysAndSignaturesAreVastlySmallerThanPostQuantum()
        {
            var ec = KeyPair.Generate(KeyType.Secp256k1);
            var pq = KeyPair.Generate(KeyType.MlDsa65);
            var message = new UTF8Encoding(false).GetBytes("size check");

            Assert.True(ec.PublicKey.Length * 20 < pq.PublicKey.Length,
                "secp256k1 public key should be at least 20x smaller");

            var ecSig = Convert.ToBase64String(ec.Sign(message)).Length;
            var pqSig = Convert.ToBase64String(pq.Sign(message)).Length;
            Assert.True(ecSig * 20 < pqSig, "secp256k1 signature should be at least 20x smaller");
        }
    }
}
