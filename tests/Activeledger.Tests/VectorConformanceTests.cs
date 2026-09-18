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
    /// Conformance against the vectors published by the ledger repository.
    ///
    /// This is what makes "done" an observation rather than an assertion: the
    /// signatures here were produced by the reference implementation and
    /// accepted by a real network, so agreeing with them is agreeing with the
    /// thing that matters.
    ///
    /// Neither scheme is reproducible. The reference signs hedged -- fresh
    /// entropy on every call -- so two signatures over one message differ, and
    /// this SDK matches that. What must hold is that signatures cross in both
    /// directions.
    /// </summary>
    public class VectorConformanceTests
    {
        private sealed record Vector(
            KeyType Type, string Name, byte[] Message,
            string PublicKey, string PrivateKey, byte[] Signature);

        private static readonly List<Vector> Vectors = Load();

        private static List<Vector> Load()
        {
            var raw = File.ReadAllText(Path.Combine("testdata", "pq-vectors.json"));
            using var doc = JsonDocument.Parse(raw);
            var result = new List<Vector>();
            foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
            {
                result.Add(new Vector(
                    KeyTypes.FromWire(v.GetProperty("type").GetString()!),
                    v.GetProperty("messageName").GetString()!,
                    new UTF8Encoding(false).GetBytes(v.GetProperty("message").GetString()!),
                    v.GetProperty("publicKey").GetString()!,
                    v.GetProperty("privateKey").GetString()!,
                    Convert.FromBase64String(v.GetProperty("signature").GetString()!)));
            }
            return result;
        }

        [Fact]
        public void TheVectorFileHasBothSchemes()
        {
            // A file that silently lost a scheme would let everything below
            // pass while covering half of what it claims.
            Assert.Contains(Vectors, v => v.Type == KeyType.MlDsa65);
            Assert.Contains(Vectors, v => v.Type == KeyType.Falcon512);
            Assert.True(Vectors.Count >= 12, $"expected at least 12 vectors, found {Vectors.Count}");
        }

        [Fact]
        public void VerifiesEveryPublishedSignature()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromPublic(v.Type, v.PublicKey);
                Assert.True(key.Verify(v.Message, v.Signature),
                    $"failed to verify published {v.Type.ToWire()}/{v.Name}");
            }
        }

        [Fact]
        public void RoundTripsPublishedKeysWithoutReDeriving()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromKeys(v.Type, v.PublicKey, v.PrivateKey);
                Assert.Equal(v.PublicKey, key.PublicKeyBase64);
                Assert.Equal(v.PrivateKey, key.PrivateKeyBase64);
            }
        }

        [Fact]
        public void SignaturesMadeHereVerifyWithTheReferencePublicKey()
        {
            foreach (var v in Vectors)
            {
                var signer = KeyPair.FromKeys(v.Type, v.PublicKey, v.PrivateKey);
                var mine = signer.Sign(v.Message);
                var verifier = KeyPair.FromPublic(v.Type, v.PublicKey);
                Assert.True(verifier.Verify(v.Message, mine),
                    $"reference key rejected a {v.Type.ToWire()} signature made here ({v.Name})");
            }
        }

        // Deliberately NOT byte equality. The reference is hedged, so matching
        // it means being unable to reproduce it -- and a signer that DID
        // reproduce it would be deterministic, a different security posture
        // adopted by accident.
        [Fact]
        public void SigningIsHedgedSoTwoSignaturesDiffer()
        {
            foreach (var v in Vectors.Take(4))
            {
                var key = KeyPair.FromKeys(v.Type, v.PublicKey, v.PrivateKey);
                Assert.NotEqual(key.Sign(v.Message), key.Sign(v.Message));
            }
        }

        [Fact]
        public void SignatureLengthsMatchTheScheme()
        {
            foreach (var v in Vectors)
            {
                var length = KeyPair.FromKeys(v.Type, v.PublicKey, v.PrivateKey).Sign(v.Message).Length;
                if (v.Type == KeyType.MlDsa65)
                {
                    Assert.Equal(3309, length);
                }
                else
                {
                    // Falcon signature length VARIES. Nothing may assume it fixed.
                    Assert.InRange(length, 600, 700);
                }
            }
        }

        [Fact]
        public void TamperedMessageDoesNotVerify()
        {
            foreach (var v in Vectors)
            {
                var key = KeyPair.FromPublic(v.Type, v.PublicKey);
                var tampered = v.Message.Concat(new byte[] { (byte)' ' }).ToArray();
                Assert.False(key.Verify(tampered, v.Signature));
            }
        }

        [Fact]
        public void MalformedSignatureReturnsFalseRatherThanThrowing()
        {
            var v = Vectors[0];
            var key = KeyPair.FromPublic(v.Type, v.PublicKey);
            Assert.False(key.Verify(v.Message, Array.Empty<byte>()));
            Assert.False(key.Verify(v.Message, new byte[10]));
            Assert.False(key.Verify(Array.Empty<byte>(), v.Signature));
        }

        [Fact]
        public void SignatureOfTheOtherSchemeReturnsFalse()
        {
            var mldsa = Vectors.First(v => v.Type == KeyType.MlDsa65);
            var falcon = Vectors.First(v => v.Type == KeyType.Falcon512);
            Assert.False(KeyPair.FromPublic(mldsa.Type, mldsa.PublicKey).Verify(mldsa.Message, falcon.Signature));
            Assert.False(KeyPair.FromPublic(falcon.Type, falcon.PublicKey).Verify(falcon.Message, mldsa.Signature));
        }

        [Fact]
        public void GeneratedKeysHaveTheDocumentedLengths()
        {
            var mldsa = KeyPair.Generate(KeyType.MlDsa65);
            Assert.Equal(1952, Convert.FromBase64String(mldsa.PublicKeyBase64).Length);
            Assert.Equal(4032, Convert.FromBase64String(mldsa.PrivateKeyBase64).Length);

            var falcon = KeyPair.Generate(KeyType.Falcon512);
            Assert.Equal(897, Convert.FromBase64String(falcon.PublicKeyBase64).Length);
            Assert.Equal(1281, Convert.FromBase64String(falcon.PrivateKeyBase64).Length);
        }

        // BouncyCastle strips the 1-byte Falcon header, so generated keys come
        // back 896/1280. A port that never adds it back produces keys the
        // ledger rejects, reported as a signature problem.
        [Fact]
        public void GeneratedFalconKeysCarryTheirHeaderBytes()
        {
            var key = KeyPair.Generate(KeyType.Falcon512);
            Assert.Equal(0x09, Convert.FromBase64String(key.PublicKeyBase64)[0]);
            Assert.Equal(0x59, Convert.FromBase64String(key.PrivateKeyBase64)[0]);
        }

        [Fact]
        public void FreshlyGeneratedKeysVerifyTheirOwnSignatures()
        {
            foreach (var type in new[] { KeyType.MlDsa65, KeyType.Falcon512 })
            {
                var key = KeyPair.Generate(type);
                var message = new UTF8Encoding(false).GetBytes("round trip");
                Assert.True(key.Verify(message, key.Sign(message)), $"{type.ToWire()} failed");
            }
        }

        [Fact]
        public void VerifyOnlyKeyPairRefusesToSign()
        {
            var v = Vectors[0];
            var key = KeyPair.FromPublic(v.Type, v.PublicKey);
            Assert.False(key.CanSign);
            Assert.Throws<InvalidOperationException>(() => key.Sign(v.Message));
            Assert.Throws<InvalidOperationException>(() => key.PrivateKeyBase64);
        }

        [Fact]
        public void WrongLengthKeyIsRejectedAtConstruction()
        {
            var tooShort = Convert.ToBase64String(new byte[100]);
            var error = Assert.Throws<ArgumentException>(() =>
                KeyPair.FromPublic(KeyType.MlDsa65, tooShort));
            Assert.Contains("1952", error.Message);
        }

        // The most likely mistake gets a specific message: "wrong length"
        // alone would not tell a caller what they actually did.
        [Fact]
        public void HeaderStrippedFalconKeyIsDiagnosedSpecifically()
        {
            var stripped = Convert.ToBase64String(new byte[896]);
            var error = Assert.Throws<ArgumentException>(() =>
                KeyPair.FromPublic(KeyType.Falcon512, stripped));
            Assert.Contains("header byte stripped", error.Message);
        }

        [Fact]
        public void KeyTypeWireStringsAreExact()
        {
            Assert.Equal("rsa", KeyType.Rsa.ToWire());
            Assert.Equal("secp256k1", KeyType.Secp256k1.ToWire());
            Assert.Equal("ml-dsa-65", KeyType.MlDsa65.ToWire());
            Assert.Equal("falcon-512", KeyType.Falcon512.ToWire());
            Assert.Throws<ArgumentException>(() => KeyTypes.FromWire("ML-DSA-65"));
        }
    }
}
