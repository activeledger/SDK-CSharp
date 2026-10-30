// The event API is deprecated; its behaviour stays tested until it is removed.
#pragma warning disable CS0618

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// The client against a real loopback socket, so connection failures,
    /// dropped connections, chunked bodies, HTTP error statuses, streaming and
    /// cancellation are exercised by the actual HTTP stack rather than a stub.
    /// Nothing leaves the machine.
    /// </summary>
    public class TransportTests
    {
        private static readonly TimeSpan Patience = TimeSpan.FromSeconds(15);

        private const string CommittedReply =
            "{\"$summary\":{\"total\":1,\"vote\":1,\"commit\":1,\"errors\":[]}," +
            "\"$streams\":{\"new\":[{\"id\":\"streamid\"}],\"updated\":[]}}";

        private const string RejectedReply =
            "{\"$summary\":{\"total\":1,\"vote\":0,\"commit\":0,\"errors\":[\"Stream(s) not found\"]}}";

        /// <summary>One request as it arrived on the wire.</summary>
        private sealed class Received
        {
            public string RequestLine { get; set; } = "";
            public Dictionary<string, string> Headers { get; } =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public byte[] Body { get; set; } = Array.Empty<byte>();
        }

        /// <summary>A minimal HTTP/1.1 server on an ephemeral loopback port.</summary>
        private sealed class Loopback : IDisposable
        {
            private readonly TcpListener _listener;
            private readonly Func<NetworkStream, Received, Task> _handler;
            private readonly CancellationTokenSource _stop = new CancellationTokenSource();
            private readonly List<Received> _requests = new List<Received>();

            public Loopback(Func<NetworkStream, Received, Task> handler)
            {
                _handler = handler;
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
                Url = "http://127.0.0.1:" + ((IPEndPoint)_listener.LocalEndpoint).Port;
                _ = Task.Run(AcceptLoop);
            }

            public string Url { get; }

            public IReadOnlyList<Received> Requests
            {
                get { lock (_requests) return _requests.ToList(); }
            }

            private async Task AcceptLoop()
            {
                while (!_stop.IsCancellationRequested)
                {
                    TcpClient socket;
                    try
                    {
                        socket = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    _ = Task.Run(() => Serve(socket));
                }
            }

            private async Task Serve(TcpClient socket)
            {
                using (socket)
                {
                    socket.NoDelay = true;
                    var stream = socket.GetStream();
                    try
                    {
                        var request = await ReadRequest(stream).ConfigureAwait(false);
                        if (request is null) return;
                        lock (_requests) _requests.Add(request);
                        await _handler(stream, request).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // The client went away mid-conversation, which several
                        // of these tests do on purpose.
                    }
                }
            }

            private static async Task<Received?> ReadRequest(NetworkStream stream)
            {
                var buffer = new MemoryStream();
                var chunk = new byte[4096];
                var headerEnd = -1;
                while (headerEnd < 0)
                {
                    var n = await stream.ReadAsync(chunk, 0, chunk.Length).ConfigureAwait(false);
                    if (n == 0) return null;
                    buffer.Write(chunk, 0, n);
                    headerEnd = IndexOfBlankLine(buffer.GetBuffer(), (int)buffer.Length);
                }

                var bytes = buffer.ToArray();
                var head = Encoding.ASCII.GetString(bytes, 0, headerEnd);
                var lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
                var received = new Received { RequestLine = lines[0] };
                foreach (var line in lines.Skip(1))
                {
                    var colon = line.IndexOf(':');
                    if (colon > 0)
                    {
                        received.Headers[line.Substring(0, colon)] = line.Substring(colon + 1).Trim();
                    }
                }

                var body = new MemoryStream();
                body.Write(bytes, headerEnd + 4, bytes.Length - headerEnd - 4);
                if (received.Headers.TryGetValue("Content-Length", out var length))
                {
                    var want = int.Parse(length);
                    while (body.Length < want)
                    {
                        var n = await stream.ReadAsync(chunk, 0, chunk.Length).ConfigureAwait(false);
                        if (n == 0) break;
                        body.Write(chunk, 0, n);
                    }
                }
                received.Body = body.ToArray();
                return received;
            }

            private static int IndexOfBlankLine(byte[] data, int length)
            {
                for (var i = 0; i + 3 < length; i++)
                {
                    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
                    {
                        return i;
                    }
                }
                return -1;
            }

            public void Dispose()
            {
                _stop.Cancel();
                _listener.Stop();
            }
        }

        private static async Task Write(NetworkStream stream, string text)
        {
            var bytes = new UTF8Encoding(false).GetBytes(text);
            await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private static Task Reply(NetworkStream stream, int status, string body, string contentType = "application/json")
        {
            var length = new UTF8Encoding(false).GetByteCount(body);
            return Write(stream,
                $"HTTP/1.1 {status} Status\r\nContent-Type: {contentType}\r\n" +
                $"Content-Length: {length}\r\nConnection: close\r\n\r\n{body}");
        }

        private static Task StartEventStream(NetworkStream stream) =>
            Write(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n");

        /// <summary>Completes when the peer closes the connection.</summary>
        private static async Task WaitForDisconnect(NetworkStream stream)
        {
            var scratch = new byte[256];
            try
            {
                while (await stream.ReadAsync(scratch, 0, scratch.Length).ConfigureAwait(false) > 0)
                {
                }
            }
            catch (IOException)
            {
            }
        }

        /// <summary>A port nothing is listening on.</summary>
        private static string ClosedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return "http://127.0.0.1:" + port;
        }

        // ---- submit ----

        [Fact]
        public async Task SubmitPostsTheEnvelopeToTheRootAndReadsTheCommit()
        {
            using var server = new Loopback((s, _) => Reply(s, 200, CommittedReply));
            using var client = new ActiveledgerClient(server.Url);
            var key = KeyPair.Generate(KeyType.Secp256k1);
            var tx = Transaction.Builder().Namespace("default").Contract("c").Input("s", key).Build();

            var response = await client.SubmitAsync(tx);

            var request = Assert.Single(server.Requests);
            Assert.Equal("POST / HTTP/1.1", request.RequestLine);
            Assert.StartsWith("application/json", request.Headers["Content-Type"]);
            Assert.Equal(tx.ToJson(), Encoding.UTF8.GetString(request.Body));
            Assert.True(response.Committed);
            Assert.Equal(new[] { "streamid" }, response.NewStreams);
        }

        // The body is signed as UTF-8, so a BOM or another encoding on the
        // wire would change the bytes the ledger re-stringifies.
        [Fact]
        public async Task NonAsciiBodiesTravelAsBomlessUtf8WithTheRightLength()
        {
            using var server = new Loopback((s, _) => Reply(s, 200, "{}"));
            using var client = new ActiveledgerClient(server.Url);
            const string body = "{\"note\":\"héllo € 🚀\"}";

            await client.SubmitRawAsync(body);

            var request = Assert.Single(server.Requests);
            var expected = new UTF8Encoding(false).GetBytes(body);
            Assert.Equal(expected, request.Body);
            Assert.Equal(expected.Length.ToString(), request.Headers["Content-Length"]);
        }

        [Fact]
        public async Task ARejectedHttp200IsNotCommittedOverARealSocket()
        {
            using var server = new Loopback((s, _) => Reply(s, 200, RejectedReply));
            using var client = new ActiveledgerClient(server.Url);

            var response = await client.SubmitRawAsync("{}");

            Assert.False(response.Committed);
            Assert.Equal(new[] { "Stream(s) not found" }, response.Errors);
        }

        // The HTTP status is not what decides the outcome, so a node that
        // reports a ledger error with a 4xx or 5xx must still surface it.
        [Theory]
        [InlineData(400)]
        [InlineData(409)]
        [InlineData(500)]
        [InlineData(503)]
        public async Task LedgerErrorsAreSurfacedWhateverTheHttpStatus(int status)
        {
            using var server = new Loopback((s, _) => Reply(s, status, RejectedReply));
            using var client = new ActiveledgerClient(server.Url);

            var response = await client.SubmitRawAsync("{}");

            Assert.False(response.Committed);
            Assert.Equal(new[] { $"HTTP status {status}", "Stream(s) not found" }, response.Errors);
            Assert.Equal(RejectedReply, response.Raw);
        }

        [Theory]
        [InlineData(404)]
        [InlineData(502)]
        public async Task ANonJsonErrorPageIsKeptVerbatimInRaw(int status)
        {
            const string page = "<html><body>gateway said no</body></html>";
            using var server = new Loopback((s, _) => Reply(s, status, page, "text/html"));
            using var client = new ActiveledgerClient(server.Url);

            var response = await client.SubmitRawAsync("{}");

            Assert.Equal(page, response.Raw);
            Assert.Empty(response.NewStreams);
        }

        [Fact]
        public async Task AChunkedReplySplitInsideATokenIsReassembled()
        {
            using var server = new Loopback(async (s, _) =>
            {
                await Write(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
                    "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                var first = CommittedReply.Substring(0, 60);
                var second = CommittedReply.Substring(60);
                await Write(s, first.Length.ToString("x") + "\r\n" + first + "\r\n");
                await Write(s, second.Length.ToString("x") + "\r\n" + second + "\r\n0\r\n\r\n");
            });
            using var client = new ActiveledgerClient(server.Url);

            var response = await client.SubmitRawAsync("{}");

            Assert.Equal(CommittedReply, response.Raw);
            Assert.Equal(new[] { "streamid" }, response.NewStreams);
        }

        [Fact]
        public async Task ALargeReplyIsReadInFull()
        {
            var padding = new string('x', 300_000);
            var body = "{\"$responses\":[{\"blob\":\"" + padding + "\"}],\"$summary\":{\"errors\":[]}}";
            using var server = new Loopback((s, _) => Reply(s, 200, body));
            using var client = new ActiveledgerClient(server.Url);

            var response = await client.SubmitRawAsync("{}");

            Assert.Equal(body.Length, response.Raw.Length);
            Assert.Equal(padding.Length, response.Responses[0].GetProperty("blob").GetString()!.Length);
        }

        // ---- transport failures ----

        [Fact]
        public async Task ARefusedConnectionSurfacesAsAnHttpRequestExceptionOnEveryCall()
        {
            using var client = new ActiveledgerClient(ClosedPort());
            var tx = Transaction.Onboard(KeyPair.Generate(KeyType.MlDsa65));

            await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRawAsync("{}"));
            await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitAsync(tx));
            // Not the InvalidOperationException reserved for a rejected onboarding.
            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.Secp256k1)));
        }

        [Fact]
        public async Task AServerThatHangsUpWithoutAReplyIsATransportFailure()
        {
            using var server = new Loopback((_, _) => Task.CompletedTask);
            using var client = new ActiveledgerClient(server.Url);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRawAsync("{}"));
            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.Falcon512)));
        }

        [Fact]
        public async Task AReplyThatIsNotHttpIsATransportFailure()
        {
            using var server = new Loopback((s, _) => Write(s, "this is not http\r\n\r\n"));
            using var client = new ActiveledgerClient(server.Url);

            await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRawAsync("{}"));
        }

        [Fact]
        public async Task ABodyCutShortOfItsContentLengthIsATransportFailure()
        {
            using var server = new Loopback((s, _) => Write(s,
                "HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{\"$summary\":"));
            using var client = new ActiveledgerClient(server.Url);

            // A truncated reply must not be handed back as a short body that
            // parses to "no errors".
            await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitRawAsync("{}"));
        }

        // ---- onboarding over the wire ----

        [Fact]
        public async Task OnboardOverARealSocketReturnsTheIdentityAndSendsASelfSignedBody()
        {
            using var server = new Loopback((s, _) => Reply(s, 200, CommittedReply));
            using var client = new ActiveledgerClient(server.Url);
            var key = KeyPair.Generate(KeyType.Secp256k1);

            var identity = await client.OnboardAsync(key);

            Assert.Equal("streamid", identity.StreamId);
            Assert.Same(key, identity.Signer);
            var body = Encoding.UTF8.GetString(Assert.Single(server.Requests).Body);
            Assert.Contains("\"$selfsign\":true", body);
            Assert.Contains(key.PublicKey, body);
        }

        [Theory]
        [InlineData("")]
        [InlineData("<html>maintenance</html>")]
        public async Task OnboardQuotesTheBodyWhenTheReplyHasNoIdentityInIt(string body)
        {
            using var server = new Loopback((s, _) => Reply(s, 200, body));
            using var client = new ActiveledgerClient(server.Url);

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.MlDsa65)));

            Assert.Contains("Onboard failed", error.Message);
            Assert.EndsWith(body, error.Message);
        }

        [Fact]
        public async Task OnboardRejectedWithAnHttpErrorStatusStillThrowsInvalidOperation()
        {
            using var server = new Loopback((s, _) => Reply(s, 500, RejectedReply));
            using var client = new ActiveledgerClient(server.Url);

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.OnboardAsync(KeyPair.Generate(KeyType.Secp256k1)));
            Assert.Contains("Stream(s) not found", error.Message);
        }

        // ---- cancellation ----

        [Fact]
        public async Task CancellingASubmitAbandonsTheConnection()
        {
            var arrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var dropped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var server = new Loopback(async (s, _) =>
            {
                arrived.TrySetResult(true);
                await WaitForDisconnect(s);
                dropped.TrySetResult(true);
            });
            using var client = new ActiveledgerClient(server.Url);
            using var cts = new CancellationTokenSource();

            var pending = client.SubmitRawAsync("{}", cts.Token);
            await arrived.Task.WaitAsync(Patience);
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            await dropped.Task.WaitAsync(Patience);
        }

        [Fact]
        public async Task CancellingAnOnboardPropagatesTheCancellation()
        {
            var arrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var server = new Loopback(async (s, _) =>
            {
                arrived.TrySetResult(true);
                await WaitForDisconnect(s);
            });
            using var client = new ActiveledgerClient(server.Url);
            using var cts = new CancellationTokenSource();

            var pending = client.OnboardAsync(KeyPair.Generate(KeyType.Falcon512), cts.Token);
            await arrived.Task.WaitAsync(Patience);
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        }

        [Fact]
        public async Task ATokenCancelledBeforeTheCallNeverReachesTheServer()
        {
            using var server = new Loopback((s, _) => Reply(s, 200, CommittedReply));
            using var client = new ActiveledgerClient(server.Url);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.SubmitRawAsync("{}", cts.Token));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.SubmitAsync(Transaction.Onboard(KeyPair.Generate(KeyType.Secp256k1)), cts.Token));

            Assert.Empty(server.Requests);
        }

        // The SDK does not own the timeout when the caller supplies the
        // HttpClient: theirs must govern, and must not be swallowed.
        [Fact]
        public async Task TheCallersHttpClientTimeoutGovernsASilentServer()
        {
            var dropped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var server = new Loopback(async (s, _) =>
            {
                await WaitForDisconnect(s);
                dropped.TrySetResult(true);
            });
            using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(150) };
            using var client = new ActiveledgerClient(server.Url, http);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SubmitRawAsync("{}"));
            await dropped.Task.WaitAsync(Patience);
        }

        // ---- event streams over a real connection ----

        [Fact]
        public async Task EventsAreDeliveredAsTheyArriveNotWhenTheStreamEnds()
        {
            var firstSeen = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var server = new Loopback(async (s, _) =>
            {
                await StartEventStream(s);
                await Write(s, "id: 1\ndata: first\n\n");
                // Held back until the client has the first event. A client
                // that buffered the whole body would never get here.
                await firstSeen.Task.WaitAsync(Patience);
                await Write(s, "id: 2\ndata: second\n\n");
            });
            using var client = new ActiveledgerClient(server.Url);

            var seen = new List<string>();
            await foreach (var e in client.SubscribeAsync("/events").WithCancellation(CancellationToken.None))
            {
                seen.Add(e.Id + ":" + e.Data);
                firstSeen.TrySetResult(true);
            }

            Assert.Equal(new[] { "1:first", "2:second" }, seen);
        }

        // Cancelling must close the socket even when the stream is idle and a
        // read is blocked on it; otherwise the node keeps the connection for a
        // subscriber that is gone.
        [Fact]
        public async Task CancellingAnIdleSubscriptionInterruptsTheBlockedReadAndClosesTheConnection()
        {
            var dropped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var server = new Loopback(async (s, _) =>
            {
                await StartEventStream(s);
                await Write(s, "data: only\n\n");
                await WaitForDisconnect(s);
                dropped.TrySetResult(true);
            });
            using var client = new ActiveledgerClient(server.Url);
            using var cts = new CancellationTokenSource();

            await using var events = client.SubscribeAsync("/events", cts.Token).GetAsyncEnumerator(cts.Token);
            Assert.True(await events.MoveNextAsync());
            Assert.Equal("only", events.Current.Data);

            var blocked = events.MoveNextAsync().AsTask();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocked);
            await dropped.Task.WaitAsync(Patience);
        }

        [Theory]
        [InlineData(401)]
        [InlineData(403)]
        [InlineData(404)]
        [InlineData(500)]
        public async Task ARejectedSubscriptionCarriesTheStatusCode(int status)
        {
            using var server = new Loopback((s, _) => Reply(s, status, "", "text/plain"));
            using var client = new ActiveledgerClient(server.Url);

            var error = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.SubscribeAsync("/events").ToListAsync());

            Assert.Equal((HttpStatusCode)status, error.StatusCode);
        }

        [Fact]
        public async Task SubscribingToARefusedConnectionThrowsRatherThanYieldingNothing()
        {
            using var client = new ActiveledgerClient(ClosedPort());

            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.SubscribeAsync("/events").ToListAsync());
        }

        [Fact]
        public async Task ASubscriptionCancelledBeforeItStartsNeverConnects()
        {
            using var server = new Loopback(async (s, _) =>
            {
                await StartEventStream(s);
                await Write(s, "data: x\n\n");
            });
            using var client = new ActiveledgerClient(server.Url);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                await foreach (var _ in client.SubscribeAsync("/events", cts.Token))
                {
                }
            });
            Assert.Empty(server.Requests);
        }
    }
}
