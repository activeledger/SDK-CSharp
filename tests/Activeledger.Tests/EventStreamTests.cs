// The event API is deprecated; its behaviour stays tested until it is removed.
#pragma warning disable CS0618

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// Event-stream framing and routing edge cases beyond the basics in
    /// <see cref="ClientTests"/>, driven through a stub transport.
    /// </summary>
    public class EventStreamTests
    {
        private sealed class Handler : HttpMessageHandler
        {
            private readonly Func<HttpResponseMessage> _reply;

            public Handler(Func<HttpResponseMessage> reply) => _reply = reply;

            public int Calls { get; private set; }
            public HttpRequestMessage? Last { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Calls++;
                Last = request;
                return Task.FromResult(_reply());
            }
        }

        private static HttpResponseMessage Stream(string body) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new MemoryStream(new UTF8Encoding(false).GetBytes(body))),
            };

        private static (ActiveledgerClient, Handler) Client(string body, string? core = null)
        {
            var handler = new Handler(() => Stream(body));
            return (new ActiveledgerClient("http://node.example:5260", new HttpClient(handler), core), handler);
        }

        [Fact]
        public async Task UnknownFieldsAndRetryHintsAreIgnored()
        {
            var (client, _) = Client("retry: 3000\nfoo: bar\nEvent: shouted\nDATA: shouted\ndata: real\n\n");

            var e = Assert.Single(await client.SubscribeAsync("/e").ToListAsync());
            Assert.Equal("real", e.Data);
            Assert.Null(e.Name);
            Assert.Null(e.Id);
        }

        // Field names are case sensitive in the event-stream format.
        [Fact]
        public async Task OnlyLowercaseFieldNamesAreRecognised()
        {
            var (client, _) = Client("Data: nope\n\nDATA: nope\n\n");

            Assert.Empty(await client.SubscribeAsync("/e").ToListAsync());
        }

        [Fact]
        public async Task AnEmptyDataFieldIsStillAnEvent()
        {
            var (client, _) = Client("data:\n\ndata: \n\n");

            var events = await client.SubscribeAsync("/e").ToListAsync();
            Assert.Equal(2, events.Count);
            Assert.All(events, e => Assert.Equal("", e.Data));
        }

        [Fact]
        public async Task EmptyDataLinesKeepTheirPlaceInAMultiLinePayload()
        {
            var (client, _) = Client("data: a\ndata:\ndata: b\n\n");

            Assert.Equal("a\n\nb", Assert.Single(await client.SubscribeAsync("/e").ToListAsync()).Data);
        }

        [Fact]
        public async Task FieldOrderWithinAnEventDoesNotMatter()
        {
            var (client, _) = Client("data: x\nid: 5\nevent: late\n\n");

            var e = Assert.Single(await client.SubscribeAsync("/e").ToListAsync());
            Assert.Equal("late", e.Name);
            Assert.Equal("5", e.Id);
            Assert.Equal("x", e.Data);
        }

        [Fact]
        public async Task ARepeatedEventFieldTakesTheLastValue()
        {
            var (client, _) = Client("event: first\nevent: second\ndata: x\n\n");

            Assert.Equal("second", Assert.Single(await client.SubscribeAsync("/e").ToListAsync()).Name);
        }

        [Fact]
        public async Task ADataValueContainingColonsIsTakenWhole()
        {
            var (client, _) = Client("data: {\"a\":\"b: c\"}\n\n");

            Assert.Equal("{\"a\":\"b: c\"}", Assert.Single(await client.SubscribeAsync("/e").ToListAsync()).Data);
        }

        [Fact]
        public async Task NonAsciiPayloadsSurviveAsUtf8()
        {
            var (client, _) = Client("event: café\ndata: € 🚀\n\n");

            var e = Assert.Single(await client.SubscribeAsync("/e").ToListAsync());
            Assert.Equal("café", e.Name);
            Assert.Equal("€ 🚀", e.Data);
        }

        [Fact]
        public async Task AVeryLongDataLineIsDeliveredWhole()
        {
            var payload = new string('z', 200_000);
            var (client, _) = Client("data: " + payload + "\n\n");

            Assert.Equal(payload, Assert.Single(await client.SubscribeAsync("/e").ToListAsync()).Data);
        }

        [Fact]
        public async Task ManyBlankLinesBetweenEventsAreHarmless()
        {
            var (client, _) = Client("\n\n\ndata: a\n\n\n\n\ndata: b\n\n\n");

            Assert.Equal(new[] { "a", "b" },
                (await client.SubscribeAsync("/e").ToListAsync()).Select(e => e.Data));
        }

        [Fact]
        public async Task AnEmptyBodyIsAnEmptyStreamNotAnError()
        {
            var (client, _) = Client("");

            Assert.Empty(await client.SubscribeAsync("/e").ToListAsync());
        }

        [Fact]
        public async Task TheRequestAsksForAnUncachedEventStream()
        {
            var (client, handler) = Client("");

            await client.SubscribeAsync("/e").ToListAsync();

            Assert.Equal(HttpMethod.Get, handler.Last!.Method);
            Assert.Equal("text/event-stream", handler.Last.Headers.Accept.Single().MediaType);
            Assert.True(handler.Last.Headers.CacheControl!.NoCache);
        }

        [Theory]
        [InlineData("HTTP://core.example:5261/e")]
        [InlineData("Https://core.example:5261/e")]
        public async Task TheUrlSchemeIsRecognisedWhateverItsCase(string url)
        {
            var (client, handler) = Client("data: x\n\n");

            await client.SubscribeAsync(url).ToListAsync();

            Assert.Equal(new Uri(url), handler.Last!.RequestUri);
        }

        [Fact]
        public async Task ActivityStreamIdsAreEscapedAsOnePathSegment()
        {
            var (client, handler) = Client("", "http://core.example:5261");

            await client.SubscribeToActivityAsync("a/b c").ToListAsync();

            Assert.Equal("http://core.example:5261/api/activity/subscribe/a%2Fb%20c",
                handler.Last!.RequestUri!.AbsoluteUri);
        }

        [Fact]
        public async Task ContractAndEventNamesAreEscapedAsSeparateSegments()
        {
            var (client, handler) = Client("", "http://core.example:5261");

            await client.SubscribeToContractEventsAsync("my contract", "a/b").ToListAsync();

            Assert.Equal("http://core.example:5261/api/events/my%20contract/a%2Fb",
                handler.Last!.RequestUri!.AbsoluteUri);
        }

        // A core URL that trims to nothing is no core URL at all.
        [Theory]
        [InlineData("")]
        [InlineData("/")]
        [InlineData("///")]
        public void ABlankCoreUrlIsReportedAsNotConfigured(string core)
        {
            var (client, handler) = Client("", core);

            Assert.Throws<InvalidOperationException>(() => client.SubscribeToActivityAsync());
            Assert.Throws<InvalidOperationException>(() => client.SubscribeToContractEventsAsync());
            Assert.Equal(0, handler.Calls);
        }

        // The malformed-arguments error wins over the missing-configuration
        // one: it is the caller's bug whatever the configuration.
        [Fact]
        public void AnEventNameWithoutAContractIsRefusedBeforeCoreIsConsulted()
        {
            var (client, _) = Client("");

            Assert.Throws<ArgumentException>(() => client.SubscribeToContractEventsAsync(null, "transfer"));
        }

        [Fact]
        public async Task CancellationFlowsThroughTheActivityAndContractWrappers()
        {
            var (client, _) = Client("data: x\n\n", "http://core.example:5261");
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.SubscribeToActivityAsync(null, cts.Token).ToListAsync());
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.SubscribeToContractEventsAsync("c", "e", cts.Token).ToListAsync());
        }

        [Theory]
        [InlineData(HttpStatusCode.Unauthorized)]
        [InlineData(HttpStatusCode.NotFound)]
        [InlineData(HttpStatusCode.InternalServerError)]
        [InlineData(HttpStatusCode.ServiceUnavailable)]
        public async Task AnyNonSuccessStatusFailsTheSubscriptionWithThatStatus(HttpStatusCode status)
        {
            var handler = new Handler(() => new HttpResponseMessage(status) { Content = new StringContent("") });
            using var client = new ActiveledgerClient("http://node.example:5260", new HttpClient(handler));

            var error = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.SubscribeAsync("/e").ToListAsync());
            Assert.Equal(status, error.StatusCode);
        }
    }
}
