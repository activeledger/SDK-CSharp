using System;
using System.Linq;
using System.Text;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// The edges of the key API: the RSA paths the SDK deliberately does not
    /// implement, wire-string parsing, and key-material handling.
    /// </summary>
    public class KeyContractTests
    {
        private static readonly byte[] Message = Encoding.UTF8.GetBytes("message");

        // RSA is a valid wire type but this SDK cannot generate, derive, sign
        // or verify with it. Each must say so rather than return a wrong key.
        [Fact]
        public void RsaKeyGenerationIsNotSupported()
        {
            var error = Assert.Throws<NotSupportedException>(() => KeyPair.Generate(KeyType.Rsa));
            Assert.Contains("rsa", error.Message);
        }

        [Fact]
        public void RsaCannotBeDerivedFromASeedOrPhrase()
        {
            Assert.Throws<NotSupportedException>(() => RecoveryPhrase.SeedSize(KeyType.Rsa));
            Assert.Throws<NotSupportedException>(() => KeyPair.FromSeed(KeyType.Rsa, new byte[32]));
            Assert.Throws<NotSupportedException>(() =>
                RecoveryPhrase.DeriveSeed(KeyType.Rsa, new byte[RecoveryPhrase.Bip39SeedSize]));
        }

        [Fact]
        public void RsaSigningAndVerifyingAreNotSupportedRatherThanReturningFalse()
        {
            var key = KeyPair.FromKeys(KeyType.Rsa, "", "");

            Assert.Throws<NotSupportedException>(() => key.Sign(Message));
            // Verify swallows malformed input as false, but must not swallow this.
            Assert.Throws<NotSupportedException>(() => key.Verify(Message, new byte[8]));
        }

        // RSA keys vary in length, so no fixed size is enforced; the key is
        // carried verbatim for a ledger that does verify RSA.
        [Fact]
        public void AnRsaPublicKeyOfAnyLengthIsCarriedVerbatim()
        {
            var blob = Convert.ToBase64String(Enumerable.Range(0, 294).Select(i => (byte)i).ToArray());
            var key = KeyPair.FromPublic(KeyType.Rsa, blob);

            Assert.Equal(blob, key.PublicKey);
            Assert.False(key.CanSign);
        }

        [Theory]
        [InlineData("rsa", KeyType.Rsa)]
        [InlineData("secp256k1", KeyType.Secp256k1)]
        [InlineData("ml-dsa-65", KeyType.MlDsa65)]
        [InlineData("falcon-512", KeyType.Falcon512)]
        public void WireStringsRoundTrip(string wire, KeyType type)
        {
            Assert.Equal(type, KeyTypes.FromWire(wire));
            Assert.Equal(wire, type.ToWire());
        }

        [Theory]
        [InlineData("ML-DSA-65")]
        [InlineData("RSA")]
        [InlineData("ed25519")]
        [InlineData("")]
        public void UnknownOrWrongCaseWireStringsAreRefusedAndNamed(string wire)
        {
            var error = Assert.Throws<ArgumentException>(() => KeyTypes.FromWire(wire));
            Assert.Contains($"'{wire}'", error.Message);
        }

        [Fact]
        public void ToWireRefusesAnUndefinedEnumValue()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => ((KeyType)99).ToWire());
        }

        [Fact]
        public void OnlyTheTwoPostQuantumSchemesArePostQuantum()
        {
            Assert.True(KeyType.MlDsa65.IsPostQuantum());
            Assert.True(KeyType.Falcon512.IsPostQuantum());
            Assert.False(KeyType.Rsa.IsPostQuantum());
            Assert.False(KeyType.Secp256k1.IsPostQuantum());
        }

        [Theory]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        [InlineData(KeyType.Secp256k1)]
        public void KeysRebuiltFromBothHalvesSignSomethingTheOriginalVerifies(KeyType type)
        {
            var original = KeyPair.Generate(type);
            var rebuilt = KeyPair.FromKeys(type, original.PublicKey, original.PrivateKey);

            Assert.True(rebuilt.CanSign);
            Assert.Equal(original.PublicKey, rebuilt.PublicKey);
            Assert.Equal(original.PrivateKey, rebuilt.PrivateKey);
            Assert.True(original.Verify(Message, rebuilt.Sign(Message)));
        }

        [Theory]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        [InlineData(KeyType.Secp256k1)]
        public void APublicOnlyKeyHasNoPrivateKeyToReveal(KeyType type)
        {
            var pub = KeyPair.FromPublic(type, KeyPair.Generate(type).PublicKey);

            Assert.False(pub.CanSign);
            var error = Assert.Throws<InvalidOperationException>(() => pub.PrivateKey);
            Assert.Contains("verification only", error.Message);
        }

        [Fact]
        public void APrivateKeyOfTheWrongLengthIsRejected()
        {
            var key = KeyPair.Generate(KeyType.MlDsa65);
            var short1 = Convert.ToBase64String(Convert.FromBase64String(key.PrivateKey).Take(100).ToArray());

            Assert.Throws<ArgumentException>(() => KeyPair.FromKeys(KeyType.MlDsa65, key.PublicKey, short1));
        }

        [Fact]
        public void ANullPrivateKeyIsReportedAsNull()
        {
            var key = KeyPair.Generate(KeyType.Falcon512);
            Assert.Throws<ArgumentNullException>(() =>
                KeyPair.FromKeys(KeyType.Falcon512, key.PublicKey, null!));
        }

        [Fact]
        public void APostQuantumPublicKeyIsStandardBase64AndSecp256k1IsPrefixedHex()
        {
            Assert.Equal(1952, Convert.FromBase64String(KeyPair.Generate(KeyType.MlDsa65).PublicKey).Length);
            Assert.Matches("^0x0[23][0-9a-f]{64}$", KeyPair.Generate(KeyType.Secp256k1).PublicKey);
        }

        [Fact]
        public void ToStringNamesTheSchemeAndNeverTheKeyMaterial()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);

            Assert.Equal("KeyPair(secp256k1, public+private)", key.ToString());
            Assert.DoesNotContain(key.PrivateKey, key.ToString());
            Assert.Equal("KeyPair(secp256k1, public only)",
                KeyPair.FromPublic(KeyType.Secp256k1, key.PublicKey).ToString());
        }

        [Fact]
        public void SigningNeverMutatesTheMessage()
        {
            var message = (byte[])Message.Clone();
            KeyPair.Generate(KeyType.Secp256k1).Sign(message);
            Assert.Equal(Message, message);
        }

        [Fact]
        public void ALegacyPhraseIsHashedAsGivenWithoutValidation()
        {
            // Not a valid mnemonic; the legacy scheme never checked, so
            // rejecting it would make an old identity unrecoverable.
            var a = KeyPair.FromLegacyPhrase("not a valid mnemonic at all");
            var b = KeyPair.FromLegacyPhrase("not a valid mnemonic at all");
            var other = KeyPair.FromLegacyPhrase("not a valid mnemonic at al1");

            Assert.Equal(a.PublicKey, b.PublicKey);
            Assert.NotEqual(a.PublicKey, other.PublicKey);
            Assert.Throws<ArgumentNullException>(() => KeyPair.FromLegacyPhrase(null!));
        }

        [Fact]
        public void ALegacyPhraseHonoursTheCompressedFlag()
        {
            Assert.Equal(33 * 2 + 2, KeyPair.FromLegacyPhrase("x", compressed: true).PublicKey.Length);
            Assert.Equal(65 * 2 + 2, KeyPair.FromLegacyPhrase("x", compressed: false).PublicKey.Length);
        }

        [Fact]
        public void DeriveSeedRefusesANullOrWrongSizedBip39Seed()
        {
            Assert.Throws<ArgumentNullException>(() => RecoveryPhrase.DeriveSeed(KeyType.MlDsa65, null!));
            Assert.Throws<ArgumentException>(() => RecoveryPhrase.DeriveSeed(KeyType.MlDsa65, new byte[63]));
        }

        [Fact]
        public void FromSeedRefusesNull()
        {
            Assert.Throws<ArgumentNullException>(() => KeyPair.FromSeed(KeyType.Secp256k1, null!));
        }

        [Fact]
        public void SeedSizesMatchEachScheme()
        {
            Assert.Equal(32, RecoveryPhrase.SeedSize(KeyType.MlDsa65));
            Assert.Equal(32, RecoveryPhrase.SeedSize(KeyType.Secp256k1));
            Assert.Equal(48, RecoveryPhrase.SeedSize(KeyType.Falcon512));
        }
    }
}
