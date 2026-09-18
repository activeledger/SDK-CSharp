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
            string PublicKey, string PrivateKey, byte[] Signature);

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
                    Convert.FromBase64String(v.GetProperty("signature").GetString()!)));
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

        /// <summary>
        /// ECDSA here uses a random k, so signatures are not reproducible --
        /// the same rule as the post-quantum schemes.
        /// </summary>
        [Fact]
        public void SigningIsNotReproducible()
        {
            var v = Vectors[0];
            var key = KeyPair.FromKeys(KeyType.Secp256k1, v.PublicKey, v.PrivateKey);

            var first = key.Sign(v.Message);
            var second = key.Sign(v.Message);

            Assert.NotEqual(first, second);
            Assert.True(key.Verify(v.Message, first));
            Assert.True(key.Verify(v.Message, second));
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
