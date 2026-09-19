using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Seed and recovery-phrase derivation, against the published
    /// cross-language vectors.
    ///
    /// Six other SDKs derive keys from the same seeds and phrases. A
    /// derivation that drifts does not fail loudly -- it produces a perfectly
    /// valid key for an identity that is not the caller's, and the only
    /// symptom arrives much later as 1220 "Signature Incorrect" from
    /// somewhere else entirely.
    /// </summary>
    public class SeedTests
    {
        private static readonly JsonDocument Doc = JsonDocument.Parse(
            File.ReadAllText(Path.Combine("testdata", "seed-vectors.json")));

        private static IEnumerable<JsonElement> SeedVectors(string type, bool valid) =>
            Doc.RootElement.GetProperty("seedVectors").EnumerateArray()
                .Where(v => v.GetProperty("type").GetString() == type
                            && Valid(v) == valid);

        private static IEnumerable<JsonElement> PhraseVectors(string type) =>
            Doc.RootElement.GetProperty("phraseVectors").EnumerateArray()
                .Where(v => v.GetProperty("type").GetString() == type);

        private static bool Valid(JsonElement v) =>
            !v.TryGetProperty("valid", out var flag) || flag.GetBoolean();

        private static byte[] Hex(string value)
        {
            var bytes = new byte[value.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        private static string Text(JsonElement v, string name) => v.GetProperty(name).GetString()!;

        private static bool Compressed(JsonElement v) =>
            !v.TryGetProperty("publicKeyForm", out var form)
            || form.GetString() == "compressed";

        public static IEnumerable<object[]> AllTypes => new[]
        {
            new object[] { "ml-dsa-65", KeyType.MlDsa65 },
            new object[] { "falcon-512", KeyType.Falcon512 },
            new object[] { "secp256k1", KeyType.Secp256k1 },
        };

        /// <summary>
        /// A file that silently lost a type would let everything below pass
        /// by simply not running.
        /// </summary>
        [Theory]
        [MemberData(nameof(AllTypes))]
        public void TheVectorFileCoversEveryType(string wire, KeyType type)
        {
            Assert.NotEmpty(SeedVectors(wire, valid: true));
            Assert.NotEmpty(PhraseVectors(wire));
            Assert.Equal(wire, type.ToWire());
        }

        [Theory]
        [MemberData(nameof(AllTypes))]
        public void FromSeedReproducesEveryPublishedKey(string wire, KeyType type)
        {
            foreach (var v in SeedVectors(wire, valid: true))
            {
                var key = KeyPair.FromSeed(type, Hex(Text(v, "seed")), Compressed(v));
                var where = $"{wire}/{Text(v, "seedName")}";

                Assert.Equal(Text(v, "publicKey"), key.PublicKey);
                Assert.Equal(Text(v, "privateKey"), key.PrivateKey);
                Assert.Equal(type, key.KeyType);
                Assert.NotNull(where);
            }
        }

        [Theory]
        [MemberData(nameof(AllTypes))]
        public void PhraseRecoveryReproducesEveryPublishedKey(string wire, KeyType type)
        {
            foreach (var v in PhraseVectors(wire))
            {
                var scheme = Text(v, "scheme");
                var key = scheme == "legacy"
                    ? KeyPair.FromLegacyPhrase(Text(v, "phrase"), Compressed(v))
                    : KeyPair.FromPhrase(type, Text(v, "phrase"), Text(v, "passphrase"), Compressed(v));

                Assert.Equal(Text(v, "publicKey"), key.PublicKey);
                Assert.Equal(Text(v, "privateKey"), key.PrivateKey);
            }
        }

        /// <summary>
        /// Checked separately from the key so a failure says WHICH step
        /// drifted.
        /// </summary>
        [Theory]
        [MemberData(nameof(AllTypes))]
        public void DerivationMatchesThePublishedIntermediates(string wire, KeyType type)
        {
            foreach (var v in PhraseVectors(wire).Where(v => Text(v, "scheme") == "v1"))
            {
                var bip39 = RecoveryPhrase.ToSeed(Text(v, "phrase"), Text(v, "passphrase"));
                Assert.Equal(Text(v, "bip39Seed"), Convert.ToHexString(bip39).ToLowerInvariant());

                var seed = RecoveryPhrase.DeriveSeed(type, bip39);
                Assert.Equal(Text(v, "derivedSeed"), Convert.ToHexString(seed).ToLowerInvariant());
            }
        }

        /// <summary>
        /// An invalid scalar must be refused, never reduced. Reducing mod n
        /// returns a perfectly functional key belonging to a different
        /// identity, and nothing downstream ever reports a problem.
        /// </summary>
        [Fact]
        public void AnInvalidScalarIsRefusedRatherThanReduced()
        {
            var seen = 0;

            foreach (var v in SeedVectors("secp256k1", valid: false))
            {
                seen++;
                var error = Assert.Throws<ArgumentException>(() =>
                    KeyPair.FromSeed(KeyType.Secp256k1, Hex(Text(v, "seed"))));

                Assert.Contains("[1, n-1]", error.Message);
            }

            Assert.True(seen >= 2, $"expected at least 2 invalid seed vectors, ran {seen}");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(31)]
        [InlineData(33)]
        [InlineData(64)]
        public void ASeedOfTheWrongLengthIsRefusedRatherThanPadded(int length)
        {
            // Padding would produce a valid key for a different identity -
            // the same failure as reducing a scalar, by another route.
            foreach (var type in new[] { KeyType.MlDsa65, KeyType.Falcon512, KeyType.Secp256k1 })
            {
                var expected = RecoveryPhrase.SeedSize(type);
                if (length == expected)
                {
                    continue;
                }

                var error = Assert.Throws<ArgumentException>(() =>
                    KeyPair.FromSeed(type, new byte[length]));

                Assert.Contains($"{expected}-byte seed", error.Message);
            }
        }

        /// <summary>
        /// Domain separation. Without it one phrase gives an ml-dsa-65 seed
        /// equal to the secp256k1 scalar, so two identities share entropy.
        /// </summary>
        [Fact]
        public void EachKeyTypeDerivesADifferentSeedFromOnePhrase()
        {
            var phrase = Text(Doc.RootElement.GetProperty("phraseVectors")[0], "phrase");
            var bip39 = RecoveryPhrase.ToSeed(phrase);

            var seeds = new[] { KeyType.MlDsa65, KeyType.Falcon512, KeyType.Secp256k1 }
                .Select(t => Convert.ToHexString(RecoveryPhrase.DeriveSeed(t, bip39)))
                .ToList();

            Assert.Equal(3, seeds.Distinct().Count());
        }

        [Fact]
        public void APassphraseChangesTheIdentityForEveryKeyType()
        {
            var phrase = Text(Doc.RootElement.GetProperty("phraseVectors")[0], "phrase");

            foreach (var type in new[] { KeyType.MlDsa65, KeyType.Falcon512, KeyType.Secp256k1 })
            {
                Assert.NotEqual(
                    KeyPair.FromPhrase(type, phrase).PublicKey,
                    KeyPair.FromPhrase(type, phrase, "TREZOR").PublicKey);
            }
        }

        [Fact]
        public void ASeedDerivedKeySignsAndVerifies()
        {
            foreach (var type in new[] { KeyType.MlDsa65, KeyType.Falcon512, KeyType.Secp256k1 })
            {
                var seed = new byte[RecoveryPhrase.SeedSize(type)];
                for (var i = 0; i < seed.Length; i++)
                {
                    seed[i] = 0x11;
                }

                var key = KeyPair.FromSeed(type, seed);
                var message = System.Text.Encoding.UTF8.GetBytes("payload");

                Assert.True(key.Verify(message, key.Sign(message)));
            }
        }

        [Fact]
        public void TheSameSeedAlwaysDerivesTheSameKey()
        {
            var seed = new byte[32];
            for (var i = 0; i < seed.Length; i++)
            {
                seed[i] = 0x5a;
            }

            Assert.Equal(
                KeyPair.FromSeed(KeyType.MlDsa65, seed).PublicKey,
                KeyPair.FromSeed(KeyType.MlDsa65, seed).PublicKey);
        }

        // -- phrase validation ------------------------------------------------

        /// <summary>
        /// An unchecked phrase is a silent failure, not a loud one: it
        /// derives a perfectly valid key for an identity nobody owns.
        /// </summary>
        [Fact]
        public void APhraseWithABadChecksumIsRejected()
        {
            var error = Assert.Throws<ArgumentException>(() =>
                RecoveryPhrase.ToSeed(string.Concat(Enumerable.Repeat("abandon ", 11)) + "abandon"));

            Assert.Contains("checksum", error.Message);
        }

        [Fact]
        public void AWordOutsideTheWordlistIsNamed()
        {
            var error = Assert.Throws<ArgumentException>(() =>
                RecoveryPhrase.ToSeed(string.Concat(Enumerable.Repeat("abandon ", 11)) + "zzzz"));

            Assert.Contains("zzzz", error.Message);
            Assert.Contains("word 12", error.Message);
        }

        [Fact]
        public void AWrongWordCountIsRejected()
        {
            var error = Assert.Throws<ArgumentException>(() =>
                RecoveryPhrase.ToSeed("abandon abandon abandon"));

            Assert.Contains("12, 15, 18, 21 or 24", error.Message);
        }

        [Fact]
        public void ExtraWhitespaceIsToleratedNotRejected()
        {
            var phrase = Text(Doc.RootElement.GetProperty("phraseVectors")[0], "phrase");

            Assert.Equal(
                KeyPair.FromPhrase(KeyType.MlDsa65, phrase).PublicKey,
                KeyPair.FromPhrase(KeyType.MlDsa65, $"  {phrase}  ").PublicKey);
        }

        /// <summary>
        /// The wordlist is an embedded resource. A build that dropped it
        /// would fail only at first use, which may be in someone else's
        /// application.
        /// </summary>
        [Fact]
        public void TheWordlistIsEmbeddedInTheAssembly()
        {
            // Validate() reaches the wordlist only after the length check, so
            // a valid-length phrase is needed to exercise the load at all.
            Assert.Throws<ArgumentException>(() =>
                RecoveryPhrase.ToSeed(string.Concat(Enumerable.Repeat("notaword ", 11)) + "notaword"));
        }
    }
}
