using System;
using System.Text;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Keys and signatures that arrive from outside - configuration, a
    /// database column, another SDK - and are malformed in ways the happy
    /// path never sees. Each must be refused with a reason, or verify as
    /// false, and never build a key that signs for the wrong identity.
    /// </summary>
    public class KeyImportAndVerifyEdgeTests
    {
        private static readonly byte[] Message = Encoding.UTF8.GetBytes("message");

        [Theory]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        public void PostQuantumKeysThatAreNotBase64AreRefusedAsSuch(KeyType type)
        {
            var key = KeyPair.Generate(type);

            var pub = Assert.Throws<ArgumentException>(() => KeyPair.FromPublic(type, "not*base64!"));
            Assert.Contains("not valid base64", pub.Message);
            var priv = Assert.Throws<ArgumentException>(
                () => KeyPair.FromKeys(type, key.PublicKey, "not*base64!"));
            Assert.Contains("not valid base64", priv.Message);
        }

        [Fact]
        public void ASecp256k1KeyWithAnOddNumberOfHexDigitsIsRefusedAndCounted()
        {
            var error = Assert.Throws<ArgumentException>(
                () => KeyPair.FromPublic(KeyType.Secp256k1, "0x" + new string('a', 65)));
            Assert.Contains("odd number of hex digits (65)", error.Message);
        }

        [Fact]
        public void AFalconPublicKeyOfTheRightLengthButTheWrongHeaderImportsButVerifiesNothing()
        {
            var key = KeyPair.Generate(KeyType.Falcon512);
            var bytes = Convert.FromBase64String(key.PublicKey);
            bytes[0] = 0x0a;
            var mangled = KeyPair.FromPublic(KeyType.Falcon512, Convert.ToBase64String(bytes));

            Assert.False(mangled.Verify(Message, key.Sign(Message)));
        }

        [Fact]
        public void AFalconPrivateKeyWithTheWrongHeaderIsNotAcceptedAsBelongingToItsPublicKey()
        {
            var key = KeyPair.Generate(KeyType.Falcon512);
            var bytes = Convert.FromBase64String(key.PrivateKey);
            bytes[0] = 0x58;

            var error = Assert.Throws<ArgumentException>(() => KeyPair.FromKeys(
                KeyType.Falcon512, key.PublicKey, Convert.ToBase64String(bytes)));
            Assert.Contains("does not belong", error.Message);
        }

        [Fact]
        public void ASecp256k1ScalarAtOrAboveTheCurveOrderIsRefused()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            const string order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

            var error = Assert.Throws<ArgumentException>(
                () => KeyPair.FromKeys(KeyType.Secp256k1, key.PublicKey, "0x" + order));
            Assert.Contains("not a valid scalar", error.Message);
            Assert.Throws<ArgumentException>(
                () => KeyPair.FromKeys(KeyType.Secp256k1, key.PublicKey, "0x" + new string('f', 64)));
        }

        [Fact]
        public void ASecp256k1PrivateKeyPairedWithAPointOffTheCurveIsRefusedAsSuch()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            // x = 5 has no y on secp256k1 (the same x the public-key checks use).
            var offCurve = "0x02" + new string('0', 63) + "5";

            Assert.Throws<ArgumentException>(
                () => KeyPair.FromKeys(KeyType.Secp256k1, offCurve, key.PrivateKey));
        }

        [Theory]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        public void PostQuantumSignaturesThatAreEmptyTruncatedOrFlippedDoNotVerify(KeyType type)
        {
            var key = KeyPair.Generate(type);
            var signature = key.Sign(Message);
            Assert.True(key.Verify(Message, signature));

            Assert.False(key.Verify(Message, Array.Empty<byte>()));
            Assert.False(key.Verify(Message, signature.AsSpan(0, signature.Length / 2).ToArray()));
            var flipped = (byte[])signature.Clone();
            flipped[flipped.Length / 2] ^= 0x01;
            Assert.False(key.Verify(Message, flipped));
        }

        [Theory]
        [InlineData(KeyType.MlDsa65)]
        [InlineData(KeyType.Falcon512)]
        [InlineData(KeyType.Secp256k1)]
        public void ASignatureDoesNotVerifyUnderAnotherKeyOfTheSameScheme(KeyType type)
        {
            var signature = KeyPair.Generate(type).Sign(Message);

            Assert.False(KeyPair.Generate(type).Verify(Message, signature));
        }

        [Fact]
        public void Secp256k1SignaturesThatAreValidDerOfTheWrongShapeAreFalseNotExceptions()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);

            // SEQUENCE of three INTEGERs, then of two OCTET STRINGs, then a
            // SEQUENCE that is not DER at all.
            Assert.False(key.Verify(Message, new byte[] { 0x30, 0x09, 2, 1, 1, 2, 1, 1, 2, 1, 1 }));
            Assert.False(key.Verify(Message, new byte[] { 0x30, 0x06, 4, 1, 1, 4, 1, 1 }));
            Assert.False(key.Verify(Message, new byte[] { 0x30, 0x05, 2, 1, 1 }));
        }

        [Fact]
        public void ADerSignatureWithZeroComponentsDoesNotVerify()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);

            // r = 0, s = 0: out of range for ECDSA and must be rejected, not crash.
            Assert.False(key.Verify(Message, new byte[] { 0x30, 0x06, 2, 1, 0, 2, 1, 0 }));
        }
    }
}
