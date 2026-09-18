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
    /// The envelope shape, and the exact bytes covered by a signature.
    ///
    /// Everything here is checked by verifying with the public key rather than
    /// by comparing signature bytes. Signing is hedged, so byte comparison
    /// would fail against a correct implementation.
    /// </summary>
    public class TransactionTests
    {
        private static KeyPair Key(KeyType type = KeyType.MlDsa65) => KeyPair.Generate(type);

        [Fact]
        public void OnboardCarriesTypeSelfsignAndLabelKeyedSigs()
        {
            var key = Key();
            var tx = Transaction.Onboard(key);

            using var doc = JsonDocument.Parse(tx.ToJson());
            var root = doc.RootElement;

            Assert.True(root.GetProperty("$selfsign").GetBoolean());

            var identity = root.GetProperty("$tx").GetProperty("$i").GetProperty("identity");
            Assert.Equal("ml-dsa-65", identity.GetProperty("type").GetString());
            Assert.Equal(key.PublicKeyBase64, identity.GetProperty("publicKey").GetString());

            // Keyed by the $i LABEL, not a stream id: there is no stream yet.
            Assert.True(root.GetProperty("$sigs").TryGetProperty("identity", out _));
        }

        [Fact]
        public void OnboardSignatureCoversTheTxObjectAndNothingElse()
        {
            var key = Key();
            var tx = Transaction.Onboard(key);

            var signature = Convert.FromBase64String(tx.Sigs["identity"]);
            Assert.True(key.Verify(tx.SignedBytes(), signature));

            // SignedBytes is $tx alone. The envelope is strictly longer, and
            // signing IT is the single most common porting mistake.
            var envelope = new UTF8Encoding(false).GetBytes(tx.ToJson());
            Assert.True(envelope.Length > tx.SignedBytes().Length);
            Assert.False(key.Verify(envelope, signature));
        }

        [Fact]
        public void OnboardWorksForEveryPostQuantumScheme()
        {
            foreach (var type in new[] { KeyType.MlDsa65, KeyType.Falcon512 })
            {
                var key = KeyPair.Generate(type);
                var tx = Transaction.Onboard(key);
                Assert.True(key.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["identity"])),
                    $"{type.ToWire()} onboard did not verify");
            }
        }

        [Fact]
        public void OnboardLabelIsConfigurable()
        {
            var tx = Transaction.Onboard(Key(), "owner");
            Assert.Contains("\"owner\"", tx.ToJson());
            Assert.True(tx.Sigs.ContainsKey("owner"));
        }

        [Fact]
        public void BuiltTransactionHasNoSelfsignKeyAtAll()
        {
            var key = Key();
            var tx = Transaction.Builder()
                .Namespace("default").Contract("transfer")
                .Input("streamid", key)
                .Build();

            // Not "false" -- absent. $selfsign: false on a normal transaction
            // changes the signed bytes for no reason.
            using var doc = JsonDocument.Parse(tx.ToJson());
            Assert.False(doc.RootElement.TryGetProperty("$selfsign", out _));
        }

        [Fact]
        public void KeyOrderFollowsInsertionNotAlphabet()
        {
            var tx = Transaction.Builder()
                .Namespace("zz").Contract("aa").Entry("mm")
                .Input("sid", Key())
                .Build();

            // $entry first, then $namespace, $contract, $i -- the order the
            // JS SDK writes, which is what the reference signs.
            var json = CanonicalJson.Stringify(tx.Body);
            Assert.StartsWith("{\"$entry\":\"mm\",\"$namespace\":\"zz\",\"$contract\":\"aa\",\"$i\":", json);
        }

        [Fact]
        public void OptionalSectionsAreOmittedWhenEmpty()
        {
            var json = CanonicalJson.Stringify(Transaction.Builder()
                .Namespace("default").Contract("noop").Input("sid", Key()).Build().Body);

            Assert.DoesNotContain("$o", json);
            Assert.DoesNotContain("$r", json);
            Assert.DoesNotContain("$entry", json);
        }

        [Fact]
        public void ReadOnlyStreamsLandInDollarR()
        {
            var tx = Transaction.Builder()
                .Namespace("default").Contract("fetch")
                .Input("sid", Key())
                .ReadOnly("target", "otherstream")
                .Build();

            using var doc = JsonDocument.Parse(tx.ToJson());
            Assert.Equal("otherstream",
                doc.RootElement.GetProperty("$tx").GetProperty("$r").GetProperty("target").GetString());
        }

        [Fact]
        public void EverySignerSignsTheSameBytes()
        {
            var a = Key();
            var b = KeyPair.Generate(KeyType.Falcon512);
            var tx = Transaction.Builder()
                .Namespace("default").Contract("multi")
                .Input("streamA", a)
                .Input("streamB", b)
                .Output("streamC")
                .Build();

            var message = tx.SignedBytes();
            Assert.True(a.Verify(message, Convert.FromBase64String(tx.Sigs["streamA"])));
            Assert.True(b.Verify(message, Convert.FromBase64String(tx.Sigs["streamB"])));
            Assert.Equal(2, tx.Sigs.Count);
        }

        [Fact]
        public void SigsAppearInTheOrderInputsWereAdded()
        {
            var tx = Transaction.Builder()
                .Namespace("default").Contract("multi")
                .Input("zebra", Key()).Input("alpha", Key())
                .Build();

            var sigs = tx.ToJson();
            Assert.True(sigs.IndexOf("zebra\":\"", StringComparison.Ordinal) <
                        sigs.IndexOf("alpha\":\"", StringComparison.Ordinal));
        }

        [Fact]
        public void ReAddingAnInputReplacesItsKeyWithoutDuplicatingTheSignature()
        {
            var replacement = Key();
            var tx = Transaction.Builder()
                .Namespace("default").Contract("c")
                .Input("sid", Key())
                .Input("sid", replacement)
                .Build();

            Assert.Single(tx.Sigs);
            Assert.True(replacement.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["sid"])));
        }

        [Fact]
        public void InputPayloadFieldsSurviveIntoTheSignedBody()
        {
            var tx = Transaction.Builder()
                .Namespace("default").Contract("transfer")
                .Input("sid", Key(), new JsonObject().Set("amount", 100L))
                .Build();

            Assert.Contains("\"amount\":100", CanonicalJson.Stringify(tx.Body));
        }

        [Theory]
        [InlineData("namespace")]
        [InlineData("contract")]
        [InlineData("input")]
        public void BuildRefusesIncompleteTransactions(string missing)
        {
            var builder = Transaction.Builder();
            if (missing != "namespace") builder.Namespace("default");
            if (missing != "contract") builder.Contract("c");
            if (missing != "input") builder.Input("sid", Key());

            Assert.Throws<InvalidOperationException>(() => builder.Build());
        }

        [Fact]
        public void EnvelopeIsRebuiltIdenticallyEachTime()
        {
            var tx = Transaction.Onboard(Key());
            Assert.Equal(tx.ToJson(), tx.ToJson());
        }
    }
}
