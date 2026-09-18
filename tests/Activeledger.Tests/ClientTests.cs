using System;
using System.Collections.Generic;
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
    /// Client behaviour driven through a stub transport, so the framing rules
    /// are checked without a network.
    /// </summary>
    public class ClientTests
    {
        /// <summary>Returns a canned body and records what was sent.</summary>
        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _reply;

            public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> reply) => _reply = reply;

            public HttpRequestMessage? LastRequest { get; private set; }
            public string? LastBody { get; private set; }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                LastRequest = request;
                if (request.Content is not null)
                {
                    LastBody = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                }
                return _reply(request);
            }
        }

        private static HttpResponseMessage Json(string body) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, new UTF8Encoding(false), "application/json"),
            };

        private static HttpResponseMessage EventStream(string body) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(
                    new MemoryStream(new UTF8Encoding(false).GetBytes(body))),
            };

        private static (ActiveledgerClient, StubHandler) Client(HttpResponseMessage reply)
        {
            var handler = new StubHandler(_ => reply);
            return (new ActiveledgerClient("http://node.example:5260", new HttpClient(handler)), handler);
        }

        // The single most dangerous default in this SDK's surface: the ledger
        // answers 200 for a REJECTED transaction. Anything that reads the HTTP
        // status as success reports a commit that never happened.
        [Fact]
        public async Task RejectionArrivesAsHttp200AndIsNotCommitted()
        {
            var (client, _) = Client(Json("{\"$summary\":{\"total\":1,\"vote\":0,\"commit\":0," +
                "\"errors\":[\"Stream(s) not found\"]}}"));

            var response = await client.SubmitRawAsync("{}");
            Assert.False(response.Committed);
            Assert.Equal(new[] { "Stream(s) not found" }, response.Errors);
        }

        [Fact]
        public async Task CommitHasNoErrors()
        {
            var (client, _) = Client(Json("{\"$summary\":{\"total\":1,\"vote\":1,\"commit\":1}," +
                "\"$streams\":{\"new\":[{\"id\":\"abc123\"}],\"updated\":[]}}"));

            var response = await client.SubmitRawAsync("{}");
            Assert.True(response.Committed);
            Assert.Equal(new[] { "abc123" }, response.NewStreams);
        }

        [Fact]
        public async Task ContractResponsesAreExposed()
        {
            var (client, _) = Client(Json("{\"$responses\":[{\"balance\":42}],\"$summary\":{\"errors\":[]}}"));

            var response = await client.SubmitRawAsync("{}");
            Assert.Single(response.Responses);
            Assert.Equal(42, response.Responses[0].GetProperty("balance").GetInt32());
        }

        // A node that returns a non-JSON body (a proxy error page, say) must
        // not throw from a property getter.
        [Fact]
        public async Task UnparseableBodyIsNotCommittedAndDoesNotThrow()
        {
            var (client, _) = Client(Json("<html>502 Bad Gateway</html>"));

            var response = await client.SubmitRawAsync("{}");
            Assert.Empty(response.Errors);
            Assert.Empty(response.NewStreams);
            Assert.Equal("<html>502 Bad Gateway</html>", response.Raw);
        }

        [Fact]
        public async Task SubmitSendsTheCanonicalEnvelopeUnaltered()
        {
            var (client, handler) = Client(Json("{\"$streams\":{\"new\":[{\"id\":\"s\"}]}}"));
            var tx = Transaction.Onboard(KeyPair.Generate(KeyType.MlDsa65));

            await client.SubmitAsync(tx);
            Assert.Equal(tx.ToJson(), handler.LastBody);
            Assert.Equal("application/json", handler.LastRequest!.Content!.Headers.ContentType!.MediaType);
        }

        [Fact]
        public async Task BaseUrlTrailingSlashDoesNotProduceADoubleSlash()
        {
            var handler = new StubHandler(_ => Json("{}"));
            using var client = new ActiveledgerClient("http://node.example:5260/", new HttpClient(handler));

            await client.SubmitRawAsync("{}");
            Assert.Equal("http://node.example:5260/", handler.LastRequest!.RequestUri!.ToString());
        }

        [Fact]
        public async Task OnboardReturnsTheNewStreamId()
        {
            var (client, _) = Client(Json("{\"$streams\":{\"new\":[{\"id\":\"streamid\"}]}}"));
            var key = KeyPair.Generate(KeyType.Falcon512);

            var identity = await client.OnboardAsync(key);
            Assert.Equal("streamid", identity.StreamId);
            Assert.Same(key, identity.Signer);
        }

        // Returning an Identity with an empty stream id would surface as a
        // confusing failure several calls later.
        [Fact]
        public async Task OnboardThrowsWhenTheLedgerRejectedIt()
        {
            var (client, _) = Client(Json("{\"$summary\":{\"errors\":[\"Stream already exists\"]}}"));

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.MlDsa65)));
            Assert.Contains("Stream already exists", error.Message);
        }

        [Fact]
        public async Task SubscribeParsesNamedEventsAndIds()
        {
            var (client, handler) = Client(EventStream(
                "event: tx\nid: 1\ndata: {\"a\":1}\n\nevent: tx\nid: 2\ndata: {\"a\":2}\n\n"));

            var events = await client.SubscribeAsync("/events").ToListAsync();

            Assert.Equal(2, events.Count);
            Assert.Equal("tx", events[0].Name);
            Assert.Equal("1", events[0].Id);
            Assert.Equal("{\"a\":1}", events[0].Data);
            Assert.Equal("2", events[1].Id);
            Assert.Equal("text/event-stream", handler.LastRequest!.Headers.Accept.Single().MediaType);
        }

        [Fact]
        public async Task MultipleDataLinesJoinWithNewlines()
        {
            var (client, _) = Client(EventStream("data: one\ndata: two\n\n"));

            var events = await client.SubscribeAsync("/events").ToListAsync();
            Assert.Equal("one\ntwo", Assert.Single(events).Data);
        }

        // Heartbeats keep the connection alive and are not events. Delivering
        // them would hand the caller a stream of empty payloads to filter.
        [Fact]
        public async Task CommentHeartbeatsAreNotDelivered()
        {
            var (client, _) = Client(EventStream(": keep-alive\n\n: another\n\ndata: real\n\n"));

            var events = await client.SubscribeAsync("/events").ToListAsync();
            Assert.Equal("real", Assert.Single(events).Data);
        }

        // event:/id: are per-event fields. Leaking them into the next event
        // mislabels it, and the mislabel looks like a server bug.
        [Fact]
        public async Task FieldsDoNotLeakIntoTheFollowingEvent()
        {
            var (client, _) = Client(EventStream("event: named\nid: 7\ndata: first\n\ndata: second\n\n"));

            var events = await client.SubscribeAsync("/events").ToListAsync();
            Assert.Equal("named", events[0].Name);
            Assert.Null(events[1].Name);
            Assert.Null(events[1].Id);
        }

        [Fact]
        public async Task CarriageReturnsAreStripped()
        {
            var (client, _) = Client(EventStream("event: tx\r\ndata: payload\r\n\r\n"));

            var e = Assert.Single(await client.SubscribeAsync("/events").ToListAsync());
            Assert.Equal("tx", e.Name);
            Assert.Equal("payload", e.Data);
        }

        // Exactly one space is framing; the rest is payload.
        [Fact]
        public async Task OnlyOneSpaceAfterTheColonIsFraming()
        {
            var (client, _) = Client(EventStream("data:  leading\n\ndata:tight\n\n"));

            var events = await client.SubscribeAsync("/events").ToListAsync();
            Assert.Equal(" leading", events[0].Data);
            Assert.Equal("tight", events[1].Data);
        }

        [Fact]
        public async Task AnEventWithoutItsTrailingBlankLineIsStillDelivered()
        {
            var (client, _) = Client(EventStream("data: truncated\n"));

            Assert.Equal("truncated", Assert.Single(await client.SubscribeAsync("/events").ToListAsync()).Data);
        }

        [Fact]
        public async Task FieldOnlyBlocksWithNoDataProduceNoEvent()
        {
            var (client, _) = Client(EventStream("event: empty\n\nid: 9\n\ndata: real\n\n"));

            Assert.Equal("real", Assert.Single(await client.SubscribeAsync("/events").ToListAsync()).Data);
        }

        [Fact]
        public async Task SubscribeUsesTheGivenPath()
        {
            var (client, handler) = Client(EventStream(""));

            await client.SubscribeAsync("/events/stream/abc").ToListAsync();
            Assert.Equal("http://node.example:5260/events/stream/abc",
                handler.LastRequest!.RequestUri!.ToString());
        }

        [Fact]
        public async Task CancellingStopsTheSubscription()
        {
            var (client, _) = Client(EventStream("data: one\n\ndata: two\n\ndata: three\n\n"));
            using var cts = new CancellationTokenSource();

            var seen = new List<string>();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                await foreach (var e in client.SubscribeAsync("/events", cts.Token))
                {
                    seen.Add(e.Data);
                    cts.Cancel();
                }
            });

            Assert.Equal(new[] { "one" }, seen);
        }

        // An injected HttpClient may be shared and is the caller's to dispose.
        [Fact]
        public void DisposingDoesNotDisposeAnInjectedHttpClient()
        {
            var http = new HttpClient(new StubHandler(_ => Json("{}")));
            using (var client = new ActiveledgerClient("http://node.example:5260", http))
            {
            }

            // Would throw ObjectDisposedException if the SDK had disposed it.
            Assert.Null(Record.Exception(() => http.Timeout));
        }

        // Event streams live on Activecore, a different service on a different
        // port. A node answers 403 for these routes, so silently aiming them at
        // BaseUrl would turn "you did not configure Activecore" into a
        // permissions error that suggests the wrong fix entirely.
        [Fact]
        public void SubscribingWithoutAnActivecoreUrlSaysSo()
        {
            var (client, _) = Client(EventStream(""));

            var error = Assert.Throws<InvalidOperationException>(
                () => client.SubscribeToActivityAsync());
            Assert.Contains("Activecore", error.Message);
        }

        [Fact]
        public async Task ActivitySubscriptionsUseTheCoreUrlAndItsRoutes()
        {
            var handler = new StubHandler(_ => EventStream(""));
            using var client = new ActiveledgerClient("http://node.example:5260",
                new HttpClient(handler), "http://core.example:5261");

            await client.SubscribeToActivityAsync().ToListAsync();
            Assert.Equal("http://core.example:5261/api/activity/subscribe",
                handler.LastRequest!.RequestUri!.ToString());

            await client.SubscribeToActivityAsync("stream:id").ToListAsync();
            Assert.Equal("http://core.example:5261/api/activity/subscribe/stream%3Aid",
                handler.LastRequest!.RequestUri!.ToString());
        }

        [Fact]
        public async Task ContractEventSubscriptionsNarrowByContractThenEvent()
        {
            var handler = new StubHandler(_ => EventStream(""));
            using var client = new ActiveledgerClient("http://node.example:5260",
                new HttpClient(handler), "http://core.example:5261/");

            await client.SubscribeToContractEventsAsync().ToListAsync();
            Assert.Equal("http://core.example:5261/api/events",
                handler.LastRequest!.RequestUri!.ToString());

            await client.SubscribeToContractEventsAsync("mycontract").ToListAsync();
            Assert.Equal("http://core.example:5261/api/events/mycontract",
                handler.LastRequest!.RequestUri!.ToString());

            await client.SubscribeToContractEventsAsync("mycontract", "transfer").ToListAsync();
            Assert.Equal("http://core.example:5261/api/events/mycontract/transfer",
                handler.LastRequest!.RequestUri!.ToString());
        }

        [Fact]
        public void AnEventNameWithoutItsContractIsRefused()
        {
            var handler = new StubHandler(_ => EventStream(""));
            using var client = new ActiveledgerClient("http://node.example:5260",
                new HttpClient(handler), "http://core.example:5261");

            Assert.Throws<ArgumentException>(
                () => client.SubscribeToContractEventsAsync(null, "transfer"));
        }

        [Fact]
        public async Task AnAbsoluteUrlBypassesBaseUrlEntirely()
        {
            var handler = new StubHandler(_ => EventStream("data: x\n\n"));
            using var client = new ActiveledgerClient("http://node.example:5260", new HttpClient(handler));

            await client.SubscribeAsync("http://storage.example:5259/db/events").ToListAsync();
            Assert.Equal("http://storage.example:5259/db/events",
                handler.LastRequest!.RequestUri!.ToString());
        }

        // A subscription that silently yields nothing is the worst possible
        // failure here: it is indistinguishable from a quiet ledger.
        [Fact]
        public async Task ARejectedSubscriptionThrowsRatherThanYieldingNothing()
        {
            var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(""),
            });
            using var client = new ActiveledgerClient("http://node.example:5260", new HttpClient(handler));

            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.SubscribeAsync("/api/events").ToListAsync());
        }
    }

    internal static class AsyncEnumerableExtensions
    {
        public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
        {
            var result = new List<T>();
            await foreach (var item in source)
            {
                result.Add(item);
            }
            return result;
        }
    }
}
