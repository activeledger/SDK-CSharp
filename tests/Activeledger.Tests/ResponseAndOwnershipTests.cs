using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Response parsing edge cases, HttpClient ownership, and builder
    /// envelope details not covered elsewhere. All through a stub transport.
    /// </summary>
    public class ResponseAndOwnershipTests
    {
        private sealed class TrackingHandler : HttpMessageHandler
        {
            private readonly string _body;
            private readonly HttpStatusCode _status;
            public TrackingHandler(string body = "{}", HttpStatusCode status = HttpStatusCode.OK)
            {
                _body = body;
                _status = status;
            }

            public bool Disposed { get; private set; }
            public int Requests { get; private set; }
            public string? Method { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Requests++;
                Method = request.Method.Method;
                return Task.FromResult(new HttpResponseMessage(_status)
                {
                    Content = new StringContent(_body, new UTF8Encoding(false), "application/json"),
                });
            }

            protected override void Dispose(bool disposing)
            {
                Disposed = true;
                base.Dispose(disposing);
            }
        }

        private static async Task<LedgerResponse> Respond(string body, HttpStatusCode status = HttpStatusCode.OK)
        {
            var client = new ActiveledgerClient(
                "http://node.example:5260", new HttpClient(new TrackingHandler(body, status)));
            return await client.SubmitRawAsync("{}");
        }

        [Fact]
        public async Task SubmitPostsToTheRoot()
        {
            var handler = new TrackingHandler();
            var client = new ActiveledgerClient("http://node.example:5260", new HttpClient(handler));

            await client.SubmitRawAsync("{}");

            Assert.Equal("POST", handler.Method);
            Assert.Equal(1, handler.Requests);
        }

        [Fact]
        public async Task DisposingTheClientLeavesAnInjectedHttpClientUsable()
        {
            var handler = new TrackingHandler();
            var http = new HttpClient(handler);
            new ActiveledgerClient("http://node.example:5260", http).Dispose();

            Assert.False(handler.Disposed);
            using var other = new ActiveledgerClient("http://node.example:5260", http);
            await other.SubmitRawAsync("{}");
            Assert.Equal(1, handler.Requests);
        }

        [Fact]
        public void DisposingTwiceIsSafeWhenTheClientOwnsItsHttpClient()
        {
            var client = new ActiveledgerClient("http://node.example:5260");
            client.Dispose();
            Assert.Null(Record.Exception(client.Dispose));
        }

        [Fact]
        public void AnInjectedHttpClientIsDisposedByNobodyButTheCaller()
        {
            var handler = new TrackingHandler();
            var http = new HttpClient(handler);
            using (new ActiveledgerClient("http://node.example:5260", http)) { }
            Assert.False(handler.Disposed);

            http.Dispose();
            Assert.True(handler.Disposed);
        }

        [Fact]
        public void TrailingSlashesAreTrimmedFromBothUrls()
        {
            using var client = new ActiveledgerClient(
                "http://node.example:5260///", coreUrl: "http://core.example:5261/");

            Assert.Equal("http://node.example:5260", client.BaseUrl);
#pragma warning disable CS0618
            Assert.Equal("http://core.example:5261", client.CoreUrl);
#pragma warning restore CS0618
        }

        [Fact]
        public void CoreUrlIsNullUnlessConfigured()
        {
            using var client = new ActiveledgerClient("http://node.example:5260");
#pragma warning disable CS0618
            Assert.Null(client.CoreUrl);
#pragma warning restore CS0618
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public async Task BlankBodiesAreNotCommittedAndDoNotThrow(string body)
        {
            var response = await Respond(body);

            Assert.False(response.Committed);
            Assert.NotEmpty(response.Errors);
            Assert.Empty(response.NewStreams);
            Assert.Empty(response.Responses);
            Assert.Equal(body, response.Raw);
            Assert.Equal(body, response.ToString());
        }

        [Theory]
        [InlineData("null")]
        [InlineData("[]")]
        [InlineData("[1,2]")]
        [InlineData("\"text\"")]
        [InlineData("42")]
        [InlineData("true")]
        [InlineData("not json")]
        public async Task ABodyThatIsNotAJsonObjectIsNotCommittedAndNeverThrows(string body)
        {
            var response = await Respond(body);

            Assert.False(response.Committed);
            Assert.NotEmpty(response.Errors);
            Assert.Empty(response.NewStreams);
            Assert.Empty(response.Responses);
        }

        [Theory]
        [InlineData("{\"$summary\":null,\"$streams\":null,\"$responses\":null}")]
        [InlineData("{\"$summary\":[],\"$streams\":[]}")]
        [InlineData("{\"$summary\":\"x\",\"$streams\":\"x\"}")]
        [InlineData("{\"$streams\":{\"new\":[1,null,\"a\",{\"id\":5}]}}")]
        public async Task MalformedSectionsNeverThrow(string body)
        {
            var response = await Respond(body);

            Assert.Empty(response.NewStreams);
            Assert.Empty(response.Responses);
            Assert.Null(Record.Exception(() => response.Errors));
            Assert.Null(Record.Exception(() => response.Committed));
        }

        [Theory]
        [InlineData(HttpStatusCode.InternalServerError)]
        [InlineData(HttpStatusCode.BadGateway)]
        [InlineData(HttpStatusCode.NotFound)]
        [InlineData(HttpStatusCode.Redirect)]
        public async Task ANon2xxStatusIsNotCommittedEvenWithACleanJsonBody(HttpStatusCode status)
        {
            var response = await Respond("{\"$summary\":{\"errors\":[]}}", status);

            Assert.False(response.Committed);
            Assert.Contains(((int)status).ToString(), response.Errors[0]);
            Assert.Equal((int)status, response.StatusCode);
        }

        [Fact]
        public async Task AnEmptyBodyOn200IsNotCommitted()
        {
            var response = await Respond("", HttpStatusCode.OK);
            Assert.False(response.Committed);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{\"$streams\":{\"new\":[{\"id\":\"s\"}]}}")]
        [InlineData("{\"$summary\":null}")]
        [InlineData("{\"$summary\":[]}")]
        [InlineData("{\"$summary\":\"ok\"}")]
        public async Task A200ObjectWithoutASummaryObjectIsNotCommitted(string body)
        {
            var response = await Respond(body);

            Assert.False(response.Committed);
            Assert.Contains("the response had no $summary object", response.Errors);
        }

        [Fact]
        public async Task ASummaryWithoutErrorsOrCommitCountIsStillCommitted()
        {
            Assert.True((await Respond("{\"$summary\":{}}")).Committed);
        }

        [Fact]
        public async Task AnHtmlGatewayPageIsNotCommitted()
        {
            var response = await Respond("<html>502</html>", HttpStatusCode.BadGateway);

            Assert.False(response.Committed);
            Assert.Equal(2, response.Errors.Count);
        }

        [Fact]
        public async Task OnboardingThrowsOnANon2xxStatus()
        {
            var http = new HttpClient(new TrackingHandler(
                "{\"$streams\":{\"new\":[{\"id\":\"abc\"}]}}", HttpStatusCode.InternalServerError));
            using var client = new ActiveledgerClient("http://node.example:5260", http);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.Secp256k1)));
        }

        [Fact]
        public async Task SeveralErrorsAreAllReportedInOrder()
        {
            var response = await Respond("{\"$summary\":{\"errors\":[\"first\",\"second\",\"third\"]}}");

            Assert.Equal(new[] { "first", "second", "third" }, response.Errors);
            Assert.False(response.Committed);
        }

        [Fact]
        public async Task NonStringErrorsAreKeptAsTheirJsonText()
        {
            var response = await Respond("{\"$summary\":{\"errors\":[{\"code\":1220}]}}");

            Assert.Single(response.Errors);
            Assert.Equal("{\"code\":1220}", response.Errors[0]);
            Assert.False(response.Committed);
        }

        [Fact]
        public async Task AnErrorsFieldThatIsNotAnArrayIsIgnored()
        {
            var response = await Respond("{\"$summary\":{\"errors\":\"boom\"}}");

            Assert.Empty(response.Errors);
            Assert.True(response.Committed);
        }

        [Fact]
        public async Task EmptyErrorsMeansCommitted()
        {
            var response = await Respond("{\"$summary\":{\"errors\":[]}}");
            Assert.True(response.Committed);
        }

        [Fact]
        public async Task NewStreamsKeepOrderAndSkipEntriesWithoutAStringId()
        {
            var response = await Respond(
                "{\"$streams\":{\"new\":[{\"id\":\"a\"},{\"name\":\"x\"},{\"id\":null},{\"id\":\"b\"}]}}");

            Assert.Equal(new[] { "a", "b" }, response.NewStreams);
        }

        [Fact]
        public async Task UpdatedStreamsAreNotReportedAsNew()
        {
            var response = await Respond("{\"$streams\":{\"new\":[],\"updated\":[{\"id\":\"u\"}]}}");
            Assert.Empty(response.NewStreams);
        }

        [Fact]
        public async Task ResponsesOfAnyJsonShapeSurviveTheDocument()
        {
            var response = await Respond("{\"$responses\":[1,\"two\",{\"k\":[3]},null]}");

            Assert.Equal(4, response.Responses.Count);
            Assert.Equal(1, response.Responses[0].GetInt32());
            Assert.Equal("two", response.Responses[1].GetString());
            Assert.Equal(3, response.Responses[2].GetProperty("k")[0].GetInt32());
            Assert.Equal(JsonValueKind.Null, response.Responses[3].ValueKind);
        }

        [Fact]
        public async Task ResponsesCanBeReadRepeatedly()
        {
            var response = await Respond("{\"$responses\":[{\"v\":1}]}");
            Assert.Equal(1, response.Responses[0].GetProperty("v").GetInt32());
            Assert.Equal(1, response.Responses[0].GetProperty("v").GetInt32());
        }

        [Fact]
        public async Task OnboardWithAnEmptyNewStreamListFailsAndQuotesTheBody()
        {
            var client = new ActiveledgerClient(
                "http://node.example:5260",
                new HttpClient(new TrackingHandler("{\"$streams\":{\"new\":[]}}")));

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.Secp256k1)));
            Assert.Contains("{\"$streams\":{\"new\":[]}}", error.Message);
        }

        [Fact]
        public async Task OnboardTakesTheFirstOfSeveralNewStreams()
        {
            var client = new ActiveledgerClient(
                "http://node.example:5260",
                new HttpClient(new TrackingHandler("{\"$summary\":{\"errors\":[]},\"$streams\":{\"new\":[{\"id\":\"one\"},{\"id\":\"two\"}]}}")));

            var identity = await client.OnboardAsync(KeyPair.Generate(KeyType.Secp256k1));
            Assert.Equal("one", identity.StreamId);
            Assert.Contains("one", identity.ToString());
        }

        // -- builder envelope ---------------------------------------------------

        [Fact]
        public void TheBuilderNeverAddsAnExpiry()
        {
            var tx = Transaction.Builder()
                .Namespace("n").Contract("c").Input("s", KeyPair.Generate(KeyType.Secp256k1)).Build();

            Assert.False(tx.Body.Has("$expire"));
            Assert.DoesNotContain("$expire", tx.ToJson());
            Assert.DoesNotContain("$expire", Transaction.Onboard(KeyPair.Generate(KeyType.Secp256k1)).ToJson());
        }

        [Fact]
        public void EntryComesFirstInTheBodyAndIsAbsentWhenNotSet()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var withEntry = Transaction.Builder().Namespace("n").Contract("c").Entry("e").Input("s", key).Build();
            var without = Transaction.Builder().Namespace("n").Contract("c").Input("s", key).Build();

            Assert.Equal(new[] { "$entry", "$namespace", "$contract", "$i" }, withEntry.Body.Keys);
            Assert.Equal(new[] { "$namespace", "$contract", "$i" }, without.Body.Keys);
        }

        [Fact]
        public void AnEmptyEntryIsTreatedAsNotSet()
        {
            var tx = Transaction.Builder().Namespace("n").Contract("c").Entry("")
                .Input("s", KeyPair.Generate(KeyType.Secp256k1)).Build();
            Assert.False(tx.Body.Has("$entry"));
        }

        [Fact]
        public void AnEmptyNamespaceOrContractIsRefusedLikeAMissingOne()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            Assert.Throws<InvalidOperationException>(() =>
                Transaction.Builder().Namespace("").Contract("c").Input("s", key).Build());
            Assert.Throws<InvalidOperationException>(() =>
                Transaction.Builder().Namespace("n").Contract("").Input("s", key).Build());
        }

        [Fact]
        public void BuildErrorsNameWhatIsMissing()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            Assert.Contains("namespace",
                Assert.Throws<InvalidOperationException>(() => Transaction.Builder().Contract("c").Input("s", key).Build()).Message);
            Assert.Contains("contract",
                Assert.Throws<InvalidOperationException>(() => Transaction.Builder().Namespace("n").Input("s", key).Build()).Message);
            Assert.Contains("input",
                Assert.Throws<InvalidOperationException>(() => Transaction.Builder().Namespace("n").Contract("c").Build()).Message);
        }

        [Fact]
        public void EnvelopeKeyOrderIsTxThenSigsAndOnboardingAddsSelfsignBetween()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var ordinary = Transaction.Builder().Namespace("n").Contract("c").Input("s", key).Build();

            Assert.Equal(new[] { "$tx", "$sigs" }, ordinary.Envelope().Keys);
            Assert.Equal(new[] { "$tx", "$selfsign", "$sigs" }, Transaction.Onboard(key).Envelope().Keys);
            Assert.False(ordinary.SelfSign);
            Assert.True(Transaction.Onboard(key).SelfSign);
        }

        [Fact]
        public void SignedBytesAreTheCanonicalBodyAndVerify()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var tx = Transaction.Builder().Namespace("n").Contract("c")
                .Input("s", key, new JsonObject().Set("amount", 5)).Build();

            Assert.Equal(CanonicalJson.Bytes(tx.Body), tx.SignedBytes());
            Assert.True(key.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["s"])));
        }

        [Fact]
        public void ChangingTheBodyInvalidatesTheSignature()
        {
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var tx = Transaction.Builder().Namespace("n").Contract("c").Input("s", key).Build();
            var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(tx.SignedBytes()).Replace("\"c\"", "\"d\""));

            Assert.False(key.Verify(tampered, Convert.FromBase64String(tx.Sigs["s"])));
        }

        [Fact]
        public void TheBuilderSignsWithTheKeyOfEachInputNotAnother()
        {
            var a = KeyPair.Generate(KeyType.Secp256k1);
            var b = KeyPair.Generate(KeyType.Secp256k1);
            var tx = Transaction.Builder().Namespace("n").Contract("c").Input("a", a).Input("b", b).Build();

            Assert.True(a.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["a"])));
            Assert.True(b.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["b"])));
            Assert.False(a.Verify(tx.SignedBytes(), Convert.FromBase64String(tx.Sigs["b"])));
        }
    }
}
