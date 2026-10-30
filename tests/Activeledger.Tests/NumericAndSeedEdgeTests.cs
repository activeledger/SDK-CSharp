using System;
using System.Globalization;
using System.Linq;
using System.Text;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Number formatting extremes, non-finite handling in every container, and
    /// the seed and recovery-phrase failure paths.
    /// </summary>
    public class NumericAndSeedEdgeTests
    {
        // Expected strings are what JSON.stringify prints for the same double.
        [Theory]
        [InlineData(5e-324, "5e-324")]                               // smallest subnormal
        [InlineData(double.MaxValue, "1.7976931348623157e+308")]
        [InlineData(-double.MaxValue, "-1.7976931348623157e+308")]
        [InlineData(2.2250738585072014e-308, "2.2250738585072014e-308")]  // smallest normal
        [InlineData(0.1 + 0.2, "0.30000000000000004")]
        [InlineData(1e300, "1e+300")]
        [InlineData(1.2345e25, "1.2345e+25")]
        [InlineData(4.5e20, "450000000000000000000")]
        [InlineData(123456789012345680000d, "123456789012345680000")]
        [InlineData(999999999999999900000d, "999999999999999900000")]
        [InlineData(0.000001234, "0.000001234")]
        [InlineData(0.0000015, "0.0000015")]
        [InlineData(1.5e-7, "1.5e-7")]
        [InlineData(-1e-7, "-1e-7")]
        [InlineData(123e-20, "1.23e-18")]
        [InlineData(4.35, "4.35")]
        [InlineData(100, "100")]
        [InlineData(-100, "-100")]
        [InlineData(9007199254740991d, "9007199254740991")]
        [InlineData(0.5, "0.5")]
        public void ExtremeAndAwkwardDoublesPrintAsJavaScriptWritesThem(double value, string expected)
        {
            Assert.Equal(expected, CanonicalJson.JsNumber(value));
        }

        // A long is widened to a double, as the ledger's JavaScript would
        // parse it, so the extremes lose their low digits.
        [Fact]
        public void LongExtremesTakeDoublePrecisionLikeEverythingElse()
        {
            Assert.Equal("{\"n\":9223372036854776000}",
                CanonicalJson.Stringify(new JsonObject().Set("n", long.MaxValue)));
            Assert.Equal("{\"n\":-9223372036854776000}",
                CanonicalJson.Stringify(new JsonObject().Set("n", long.MinValue)));
            Assert.Equal("[0,1,-1]",
                CanonicalJson.Stringify(new JsonArray().Add(0L).Add(1L).Add(-1L)));
        }

        [Fact]
        public void NegativeZeroInsideAnObjectOrArrayPrintsAsZero()
        {
            Assert.Equal("{\"n\":0}", CanonicalJson.Stringify(new JsonObject().Set("n", -0.0)));
            Assert.Equal("[0]", CanonicalJson.Stringify(new JsonArray().Add(-0.0)));
        }

        [Fact]
        public void EveryNumberThatRoundTripsThroughTheFormatterParsesBack()
        {
            var values = new[] { 5e-324, 1.1, 1e-7, 123456.789, 1e21, 2.5e-10, 7e22, double.MaxValue };
            foreach (var value in values)
            {
                var text = CanonicalJson.JsNumber(value);
                Assert.Equal(value, double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture));
            }
        }

        [Theory]
        [InlineData(double.PositiveInfinity, "Infinity")]
        [InlineData(double.NegativeInfinity, "Infinity")]
        [InlineData(double.NaN, "NaN")]
        public void NonFiniteNumbersAreRefusedInEveryPosition(double value, string named)
        {
            var inObject = new JsonObject().Set("n", value);
            var inArray = new JsonArray().Add(value);
            var nested = new JsonObject().Set("outer",
                new JsonObject().Set("list", new JsonArray().Add(1L).Add(value)));
            var bare = new JsonNumber(value);

            foreach (IJsonValue v in new IJsonValue[] { inObject, inArray, nested, bare })
            {
                var error = Assert.Throws<ArgumentException>(() => CanonicalJson.Stringify(v));
                Assert.Contains(named, error.Message);
                Assert.Throws<ArgumentException>(() => CanonicalJson.Bytes(v));
            }
        }

        // A transaction carrying a non-finite number must not sign: signing
        // JSON.stringify's "null" for it would put bytes on the ledger the
        // caller never wrote.
        [Fact]
        public void ABuilderWithANonFinitePayloadRefusesToSign()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var builder = Transaction.Builder().Namespace("n").Contract("c")
                .Input("s", key, new JsonObject().Set("amount", double.NaN));

            Assert.Throws<ArgumentException>(() => builder.Build());
        }

        // ---- seeds and phrases ----

        [Fact]
        public void NullPhrasesAreRefusedByEveryEntryPoint()
        {
            Assert.Throws<ArgumentNullException>(() => RecoveryPhrase.Validate(null!));
            Assert.Throws<ArgumentNullException>(() => RecoveryPhrase.ToSeed(null!));
            Assert.Throws<ArgumentNullException>(() => KeyPair.FromPhrase(KeyType.MlDsa65, null!));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(11)]
        [InlineData(13)]
        [InlineData(14)]
        [InlineData(16)]
        [InlineData(20)]
        [InlineData(22)]
        [InlineData(25)]
        [InlineData(36)]
        public void OnlyTheFiveBip39LengthsAreAccepted(int words)
        {
            var phrase = string.Join(" ", Enumerable.Repeat("abandon", words));

            var error = Assert.Throws<ArgumentException>(() => RecoveryPhrase.Validate(phrase));

            Assert.Contains($"got {words}", error.Message);
        }

        [Theory]
        [InlineData(KeyType.Secp256k1)]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        public void ABadPhraseIsRefusedBeforeAnyKeyIsDerived(KeyType type)
        {
            var typo = string.Join(" ", Enumerable.Repeat("abandon", 12));

            Assert.Throws<ArgumentException>(() => KeyPair.FromPhrase(type, typo));
            Assert.Throws<ArgumentException>(() => KeyPair.FromPhrase(type, "not a phrase at all"));
        }

        [Fact]
        public void AWordOutsideTheListIsReportedWithItsPosition()
        {
            var phrase = "abandon abandon abandon abandon abandon abandon " +
                         "abandon abandon abandon abandon abandon zzzzzz";

            var error = Assert.Throws<ArgumentException>(() => RecoveryPhrase.Validate(phrase));

            Assert.Contains("word 12", error.Message);
            Assert.Contains("zzzzzz", error.Message);
        }

        // The wordlist is lowercase, and matching is exact: a capitalised
        // phrase is rejected, not silently folded to a different identity.
        [Fact]
        public void ACapitalisedPhraseIsRefusedNotFolded()
        {
            var phrase = "Abandon abandon abandon abandon abandon abandon " +
                         "abandon abandon abandon abandon abandon about";

            var error = Assert.Throws<ArgumentException>(() => RecoveryPhrase.Validate(phrase));

            Assert.Contains("word 1", error.Message);
        }

        [Fact]
        public void TabsAndNewlinesBetweenWordsNormaliseToSingleSpaces()
        {
            var phrase = "abandon\tabandon\nabandon  abandon\r\nabandon abandon " +
                         "abandon abandon abandon abandon abandon\tabout";

            Assert.Equal(
                "abandon abandon abandon abandon abandon abandon " +
                "abandon abandon abandon abandon abandon about",
                RecoveryPhrase.Validate(phrase));
        }

        [Fact]
        public void ANullPassphraseIsTheSameAsAnEmptyOne()
        {
            const string phrase = "abandon abandon abandon abandon abandon abandon " +
                                  "abandon abandon abandon abandon abandon about";

            Assert.Equal(RecoveryPhrase.ToSeed(phrase, ""), RecoveryPhrase.ToSeed(phrase, null!));
            Assert.Equal(RecoveryPhrase.Bip39SeedSize, RecoveryPhrase.ToSeed(phrase).Length);
        }

        [Fact]
        public void TheWorstCaseSeedBoundariesOfSecp256k1AreEnforcedExactly()
        {
            // n, the group order, is the first value that is NOT a valid scalar.
            const string n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
            const string nMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
            var one = new byte[32];
            one[31] = 1;

            Assert.Throws<ArgumentException>(() => KeyPair.FromSeed(KeyType.Secp256k1, new byte[32]));
            Assert.Throws<ArgumentException>(() => KeyPair.FromSeed(KeyType.Secp256k1, Hex(n)));
            Assert.Throws<ArgumentException>(() =>
                KeyPair.FromSeed(KeyType.Secp256k1, Enumerable.Repeat((byte)0xff, 32).ToArray()));

            Assert.True(KeyPair.FromSeed(KeyType.Secp256k1, one).CanSign);
            Assert.True(KeyPair.FromSeed(KeyType.Secp256k1, Hex(nMinusOne)).CanSign);
        }

        private const string Phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Precomposed and decomposed spellings of the same passphrase must give
        // the same seed (BIP-39 requires NFKD) -- or, where the runtime cannot
        // normalise (this project runs InvariantGlobalization), be refused
        // rather than silently derive a different key.
        [Fact]
        public void EquivalentUnicodeSpellingsOfAPassphraseNeverDeriveDifferentSeeds()
        {
            var precomposed = "caf\u00e9";
            var decomposed = "cafe\u0301";
            var normalises = "\u00e9".Normalize(System.Text.NormalizationForm.FormKD).Length == 2;

            if (normalises)
            {
                Assert.Equal(
                    RecoveryPhrase.ToSeed(Phrase, precomposed),
                    RecoveryPhrase.ToSeed(Phrase, decomposed));
            }
            else
            {
                Assert.Throws<PlatformNotSupportedException>(() => RecoveryPhrase.ToSeed(Phrase, precomposed));
                Assert.Throws<PlatformNotSupportedException>(() => RecoveryPhrase.ToSeed(Phrase, decomposed));
            }
        }

        [Fact]
        public void AnAsciiPassphraseNeedsNoNormalisation()
        {
            Assert.Equal(64, RecoveryPhrase.ToSeed(Phrase, "TREZOR").Length);
        }

        [Fact]
        public void TheCompressedFlagChoosesTheSecp256k1PublicKeyForm()
        {
            var seed = new byte[32];
            seed[31] = 7;

            var compressed = KeyPair.FromSeed(KeyType.Secp256k1, seed, compressed: true);
            var uncompressed = KeyPair.FromSeed(KeyType.Secp256k1, seed, compressed: false);

            Assert.Equal(2 + 66, compressed.PublicKey.Length);
            Assert.Equal(2 + 130, uncompressed.PublicKey.Length);
            Assert.StartsWith("0x04", uncompressed.PublicKey);
            Assert.True(compressed.PublicKey.StartsWith("0x02") || compressed.PublicKey.StartsWith("0x03"));
            // Same private scalar, so each signs for the other's public form.
            Assert.Equal(compressed.PrivateKey, uncompressed.PrivateKey);
        }

        private static byte[] Hex(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
