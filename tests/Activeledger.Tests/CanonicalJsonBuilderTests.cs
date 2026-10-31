using System;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// The JsonObject and JsonArray builders: the parts of the canonical JSON
    /// surface that are not number or string formatting.
    /// </summary>
    public class CanonicalJsonBuilderTests
    {
        private sealed class Foreign : IJsonValue { }

        [Fact]
        public void GetReturnsTheStoredValueOrNullAndHasAgrees()
        {
            var obj = new JsonObject().Set("a", 1).SetNull("n");

            Assert.NotNull(obj.Get("a"));
            Assert.True(obj.Has("a"));
            Assert.Null(obj.Get("missing"));
            Assert.False(obj.Has("missing"));
            // A present null is still present.
            Assert.Null(obj.Get("n"));
            Assert.True(obj.Has("n"));
        }

        [Fact]
        public void ANullKeptInAnObjectOrArrayIsWrittenAsNull()
        {
            var arr = new JsonArray().Add(1).AddNull().Add(true);
            var obj = new JsonObject().SetNull("n").Set("arr", arr);

            Assert.Equal("{\"n\":null,\"arr\":[1,null,true]}", CanonicalJson.Stringify(obj));
            Assert.Equal(3, arr.Count);
        }

        [Fact]
        public void AValueTypeTheSerializerDoesNotKnowIsRefusedNotGuessed()
        {
            var error = Assert.Throws<ArgumentException>(
                () => CanonicalJson.Stringify(new JsonObject().Set("x", new Foreign())));
            Assert.Contains("Foreign", error.Message);
        }
    }
}
