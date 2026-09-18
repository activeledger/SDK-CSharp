using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Checked against the bytes the JavaScript reference produced and a real
    /// ledger accepted. If this file and my reading of JSON.stringify ever
    /// disagree, this file is right.
    /// </summary>
    public class CanonicalJsonTests
    {
        private static readonly Dictionary<string, string> Reference = LoadReference();

        private static Dictionary<string, string> LoadReference()
        {
            var raw = File.ReadAllText(Path.Combine("testdata", "pq-vectors.json"));
            using var doc = JsonDocument.Parse(raw);
            var result = new Dictionary<string, string>();
            foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
            {
                var name = v.GetProperty("messageName").GetString()!;
                if (!result.ContainsKey(name))
                {
                    result[name] = v.GetProperty("message").GetString()!;
                }
            }
            return result;
        }

        [Fact]
        public void AsciiBaseline()
        {
            Assert.Equal(Reference["ascii"],
                CanonicalJson.Stringify(new JsonObject().Set("greeting", "hello")));
        }

        // System.Text.Json escapes these by default; so does Go. Both look
        // fine until a payload contains an angle bracket.
        [Fact]
        public void HtmlCharactersAreNotEscaped()
        {
            var built = new JsonObject()
                .Set("expr", "a < b && c > d")
                .Set("amp", "Tom & Jerry");
            Assert.Equal(Reference["html"], CanonicalJson.Stringify(built));
        }

        // System.Text.Json escapes non-ASCII to \uXXXX by default. That is the
        // same class of bug as Python's ensure_ascii.
        [Fact]
        public void NonAsciiIsRaw()
        {
            var built = new JsonObject().Set("greeting", "café 日本語 ☕");
            var got = CanonicalJson.Stringify(built);
            Assert.Equal(Reference["non-ascii"], got);
            Assert.DoesNotContain("\\u00e9", got);
        }

        [Fact]
        public void WholeFloatsPrintAsIntegers()
        {
            var built = new JsonObject()
                .Set("whole", 1.0)
                .Set("third", 0.1)
                .Set("negative", -2.5)
                .Set("zero", 0L);
            Assert.Equal(Reference["float"], CanonicalJson.Stringify(built));
        }

        // The ledger does not canonicalise key order, so the signer reproduces
        // whatever order the caller built. These keys are not alphabetical.
        [Fact]
        public void KeyOrderIsInsertionOrderNotSorted()
        {
            var built = new JsonObject().Set("zebra", 1L).Set("alpha", 2L).Set("middle", 3L);
            Assert.Equal(Reference["ordering"], CanonicalJson.Stringify(built));
        }

        // Documents why this serialiser exists rather than merely asserting
        // behaviour: if System.Text.Json ever stops escaping by default, this
        // test says so.
        [Fact]
        public void SystemTextJsonStillGetsItWrong()
        {
            var stdlib = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["expr"] = "a < b && c > d",
            });
            Assert.NotEqual(Reference["html"], stdlib);
            Assert.Contains("\\u003C", stdlib, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void OnboardShapeMatchesReference()
        {
            var reference = Reference["onboard"];
            using var doc = JsonDocument.Parse(reference);
            var identity = doc.RootElement.GetProperty("$i").GetProperty("identity");

            var built = new JsonObject()
                .Set("$namespace", "default")
                .Set("$contract", "onboard")
                .Set("$i", new JsonObject().Set("identity", new JsonObject()
                    .Set("type", identity.GetProperty("type").GetString()!)
                    .Set("publicKey", identity.GetProperty("publicKey").GetString()!)))
                .Set("$o", new JsonObject());

            Assert.Equal(reference, CanonicalJson.Stringify(built));
        }

        [Fact]
        public void NestedStructuresArraysAndNull()
        {
            var built = new JsonObject()
                .Set("a", new JsonArray().Add(1L).Add("two").Add(true).AddNull())
                .Set("b", new JsonObject().Set("c", false));
            Assert.Equal("{\"a\":[1,\"two\",true,null],\"b\":{\"c\":false}}",
                CanonicalJson.Stringify(built));
        }

        [Fact]
        public void EmptyContainers()
        {
            Assert.Equal("{}", CanonicalJson.Stringify(new JsonObject()));
            Assert.Equal("[]", CanonicalJson.Stringify(new JsonArray()));
        }

        [Fact]
        public void EscapesOnlyWhatJsonRequires()
        {
            var built = new JsonObject().Set("s", "a\"b\\c");
            Assert.Equal("{\"s\":\"a\\\"b\\\\c\"}", CanonicalJson.Stringify(built));
        }

        [Fact]
        public void ControlCharacters()
        {
            var built = new JsonObject().Set("s", "\n\t" + (char)1);
            Assert.Equal("{\"s\":\"\\n\\t\\u0001\"}", CanonicalJson.Stringify(built));
        }

        [Theory]
        [InlineData(double.NaN)]
        [InlineData(double.PositiveInfinity)]
        [InlineData(double.NegativeInfinity)]
        public void NanAndInfinityRefused(double bad)
        {
            Assert.Throws<ArgumentException>(() =>
                CanonicalJson.Stringify(new JsonObject().Set("x", bad)));
        }

        [Fact]
        public void ReplacingAKeyKeepsItsPosition()
        {
            var built = new JsonObject().Set("a", 1L).Set("b", 2L).Set("a", 3L);
            Assert.Equal("{\"a\":3,\"b\":2}", CanonicalJson.Stringify(built));
        }

        [Fact]
        public void BytesAreUtf8OfTheString()
        {
            var built = new JsonObject().Set("e", "é");
            Assert.Equal(new UTF8Encoding(false).GetBytes(CanonicalJson.Stringify(built)),
                CanonicalJson.Bytes(built));
            Assert.Equal(10, CanonicalJson.Bytes(built).Length);
        }
    }
}
