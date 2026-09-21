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
    /// Canonical number formatting, against the published vectors.
    ///
    /// What gets signed is JSON.stringify($tx) and the ledger verifies against
    /// a re-stringified $tx, so JavaScript's number formatting is the
    /// specification. A number written differently produces a signature the
    /// ledger rejects as 1220, with nothing in the message about numbers.
    ///
    /// These exist because the `float` case in pq-vectors.json -- 1, 0.1,
    /// -2.5, 0 -- sits entirely inside the range where every language agrees.
    /// </summary>
    public class NumberTests
    {
        private static readonly JsonDocument Doc = JsonDocument.Parse(
            File.ReadAllText(Path.Combine("testdata", "number-vectors.json")));

        public static IEnumerable<object[]> Vectors =>
            Doc.RootElement.GetProperty("vectors").EnumerateArray()
                .Select(v => new object[]
                {
                    v.GetProperty("name").GetString()!,
                    v.GetProperty("value").GetDouble(),
                    v.GetProperty("expected").GetString()!,
                });

        [Fact]
        public void TheVectorFileIsNotEmpty()
        {
            Assert.NotEmpty(Vectors);
        }

        [Theory]
        [MemberData(nameof(Vectors))]
        public void JsNumberMatchesTheReference(string name, double value, string expected)
        {
            Assert.Equal(expected, CanonicalJson.JsNumber(value));
            Assert.NotNull(name);
        }

        /// <summary>
        /// The formatter being right is not enough if the encoder does not
        /// call it.
        /// </summary>
        [Theory]
        [MemberData(nameof(Vectors))]
        public void TheEncoderUsesIt(string name, double value, string expected)
        {
            var encoded = CanonicalJson.Stringify(new JsonObject().Set("n", value));

            Assert.Equal("{\"n\":" + expected + "}", encoded);
            Assert.NotNull(name);
        }

        [Fact]
        public void NegativeZeroLosesItsSign()
        {
            Assert.Equal("0", CanonicalJson.JsNumber(-0.0));
        }

        /// <summary>ToString("R") gives 1E+21; JavaScript writes 1e+21.</summary>
        [Fact]
        public void ExponentIsLowercaseWithNoLeadingZeros()
        {
            Assert.Equal("1e+21", CanonicalJson.JsNumber(1e21));
            Assert.Equal("1e-7", CanonicalJson.JsNumber(1e-7));
            Assert.Equal("-1.5e-9", CanonicalJson.JsNumber(-1.5e-9));
        }

        /// <summary>Both sides of both boundaries.</summary>
        [Fact]
        public void ThePlainExponentBoundaries()
        {
            Assert.Equal("100000000000000000000", CanonicalJson.JsNumber(1e20));
            Assert.Equal("1e+21", CanonicalJson.JsNumber(1e21));
            Assert.Equal("0.000001", CanonicalJson.JsNumber(1e-6));
            Assert.Equal("1e-7", CanonicalJson.JsNumber(1e-7));
        }

        /// <summary>
        /// (long)value is undefined above long.MaxValue in an unchecked
        /// context, so 1e19 used to come out as long.MinValue.
        /// </summary>
        [Fact]
        public void LargeWholeValuesNoLongerOverflowTheLongCast()
        {
            Assert.Equal("10000000000000000000", CanonicalJson.JsNumber(1e19));
            Assert.DoesNotContain("-", CanonicalJson.JsNumber(1e19));
            Assert.DoesNotContain("-", CanonicalJson.JsNumber(1e20));
        }

        [Fact]
        public void IntegersBeyondTwoToThe53TakeDoublePrecision()
        {
            // JavaScript has no integer type, so the ledger parses this into a
            // double whatever is sent.
            Assert.Equal("9007199254740992", CanonicalJson.JsNumber(9007199254740993d));
        }

        [Fact]
        public void NonFiniteIsRefused()
        {
            var obj = new JsonObject().Set("n", double.NaN);
            Assert.Throws<ArgumentException>(() => CanonicalJson.Stringify(obj));
        }
    }
}
