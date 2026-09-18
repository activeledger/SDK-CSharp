using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Activeledger
{
    /// <summary>The ledger's reply to a submitted transaction.</summary>
    public sealed class LedgerResponse
    {
        private readonly JsonDocument? _doc;

        internal LedgerResponse(string raw)
        {
            Raw = raw;
            try
            {
                _doc = string.IsNullOrWhiteSpace(raw) ? null : JsonDocument.Parse(raw);
            }
            catch (JsonException)
            {
                _doc = null;
            }
        }

        /// <summary>The response body exactly as the node sent it.</summary>
        public string Raw { get; }

        /// <summary>
        /// Errors the network reported.
        /// </summary>
        /// <remarks>
        /// Non-empty means the transaction did NOT commit, even though the HTTP
        /// status was 200. The ledger answers 200 for a rejected transaction,
        /// so treating HTTP success as ledger success is wrong -- and wrong in
        /// a way that looks fine until something important silently did not
        /// happen.
        /// </remarks>
        public IReadOnlyList<string> Errors
        {
            get
            {
                var result = new List<string>();
                if (_doc is null) return result;
                if (_doc.RootElement.TryGetProperty("$summary", out var summary) &&
                    summary.TryGetProperty("errors", out var errors) &&
                    errors.ValueKind == JsonValueKind.Array)
                {
                    foreach (var error in errors.EnumerateArray())
                    {
                        result.Add(error.ToString());
                    }
                }
                return result;
            }
        }

        /// <summary>True when <see cref="Errors"/> is empty. This, not the HTTP status.</summary>
        public bool Committed => Errors.Count == 0;

        /// <summary>Stream ids this transaction created.</summary>
        public IReadOnlyList<string> NewStreams
        {
            get
            {
                var result = new List<string>();
                if (_doc is null) return result;
                if (_doc.RootElement.TryGetProperty("$streams", out var streams) &&
                    streams.TryGetProperty("new", out var created) &&
                    created.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in created.EnumerateArray())
                    {
                        if (item.TryGetProperty("id", out var id) && id.GetString() is { } value)
                        {
                            result.Add(value);
                        }
                    }
                }
                return result;
            }
        }

        /// <summary>Values contracts handed back with <c>returnToRemote</c>.</summary>
        public IReadOnlyList<JsonElement> Responses
        {
            get
            {
                var result = new List<JsonElement>();
                if (_doc is null) return result;
                if (_doc.RootElement.TryGetProperty("$responses", out var responses) &&
                    responses.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in responses.EnumerateArray())
                    {
                        result.Add(item.Clone());
                    }
                }
                return result;
            }
        }

        /// <summary>The raw body.</summary>
        public override string ToString() => Raw;
    }

    /// <summary>An onboarded identity: its stream id and the key controlling it.</summary>
    public sealed class Identity
    {
        internal Identity(string streamId, ISigner signer)
        {
            StreamId = streamId;
            Signer = signer;
        }

        /// <summary>The identity's stream id on the ledger.</summary>
        public string StreamId { get; }

        /// <summary>The key controlling this identity.</summary>
        public ISigner Signer { get; }

        /// <summary>A short description, with the stream id truncated.</summary>
        public override string ToString() =>
            $"Identity({StreamId.Substring(0, Math.Min(12, StreamId.Length))}..., {Signer.KeyType.ToWire()})";
    }

    /// <summary>One server-sent event.</summary>
    public sealed class LedgerEvent
    {
        internal LedgerEvent(string? name, string data, string? id)
        {
            Name = name;
            Data = data;
            Id = id;
        }

        /// <summary>The <c>event:</c> field, or null when unnamed.</summary>
        public string? Name { get; }

        /// <summary>The <c>data:</c> payload. Multiple data lines join with newlines.</summary>
        public string Data { get; }

        /// <summary>The <c>id:</c> field, or null when absent.</summary>
        public string? Id { get; }
    }

    /// <summary>A connection to one Activeledger node.</summary>
    public sealed class ActiveledgerClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;

        /// <summary>
        /// Connects to a node, and optionally to an Activecore instance.
        /// </summary>
        /// <param name="baseUrl">
        /// The node's transaction URL, for example <c>http://localhost:5260</c>.
        /// </param>
        /// <param name="http">
        /// An HttpClient to use. When supplied it is the caller's to dispose,
        /// which is what lets it be shared or configured with a proxy, a
        /// timeout or client certificates.
        /// </param>
        /// <param name="coreUrl">
        /// The Activecore URL, which serves the event streams. This is a
        /// SEPARATE service on its own port, not a path on the node: a node
        /// answers 403 for every event route, so defaulting it to
        /// <paramref name="baseUrl"/> would turn a missing Activecore into a
        /// puzzling permissions error. Leave it unset unless subscribing.
        /// </param>
        public ActiveledgerClient(string baseUrl, HttpClient? http = null, string? coreUrl = null)
        {
            BaseUrl = baseUrl.TrimEnd('/');
            CoreUrl = coreUrl?.TrimEnd('/');
            _ownsHttp = http is null;
            _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        /// <summary>The node URL, without a trailing slash.</summary>
        public string BaseUrl { get; }

        /// <summary>The Activecore URL, without a trailing slash, or null if not configured.</summary>
        public string? CoreUrl { get; }

        /// <summary>Submits a signed transaction.</summary>
        public Task<LedgerResponse> SubmitAsync(Transaction transaction, CancellationToken cancellationToken = default) =>
            SubmitRawAsync(transaction.ToJson(), cancellationToken);

        /// <summary>
        /// Submits a pre-built envelope.
        /// </summary>
        /// <remarks>
        /// For envelopes built elsewhere, and for testing rejection paths -- a
        /// tampered body cannot be expressed through <see cref="SubmitAsync"/>,
        /// because the builder would re-sign it into a valid transaction.
        /// </remarks>
        public async Task<LedgerResponse> SubmitRawAsync(string body, CancellationToken cancellationToken = default)
        {
            using var content = new StringContent(body, new UTF8Encoding(false), "application/json");
            using var response = await _http.PostAsync(BaseUrl + "/", content, cancellationToken)
                .ConfigureAwait(false);
            var raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return new LedgerResponse(raw);
        }

        /// <summary>
        /// Onboards a new identity.
        /// </summary>
        /// <remarks>
        /// Throws if the ledger rejected it, rather than returning an Identity
        /// with an empty stream id -- an onboarding that silently produced no
        /// identity is a failure that surfaces three calls later.
        /// </remarks>
        public async Task<Identity> OnboardAsync(ISigner signer, CancellationToken cancellationToken = default)
        {
            var response = await SubmitAsync(Transaction.Onboard(signer), cancellationToken).ConfigureAwait(false);
            if (response.NewStreams.Count == 0)
            {
                throw new InvalidOperationException($"Onboard failed: {response.Raw}");
            }
            return new Identity(response.NewStreams[0], signer);
        }

        /// <summary>
        /// Subscribes to server-sent events.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Cancelling the token closes the connection -- the same guarantee the
        /// other SDKs give. With a callback API that would be the caller's job
        /// and the thing they forget, leaving a node holding connections for
        /// subscribers that are gone.
        /// </para>
        /// <para>
        /// The parser handles the framing rules that matter: multiple
        /// <c>data:</c> lines concatenate with newlines, <c>:</c> comment lines
        /// (heartbeats) are ignored rather than delivered as empty events, and
        /// <c>event:</c>/<c>id:</c> do not leak into the following event.
        /// </para>
        /// </remarks>
        public async IAsyncEnumerable<LedgerEvent> SubscribeAsync(
            string pathOrUrl,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var target = pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                         pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? pathOrUrl
                : BaseUrl + pathOrUrl;

            using var request = new HttpRequestMessage(HttpMethod.Get, target);
            request.Headers.Add("Accept", "text/event-stream");
            request.Headers.Add("Cache-Control", "no-cache");

            using var response = await _http
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            // Without this a rejected subscription becomes an empty event
            // stream: the caller waits forever for events that were never
            // coming, and nothing anywhere reports a problem. Pointing a
            // subscription at a node instead of Activecore returns 403, and
            // that is a mistake worth being told about immediately.
            response.EnsureSuccessStatusCode();

            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var reader = new StreamReader(stream, new UTF8Encoding(false));

            // Disposing the stream is what actually interrupts a pending read.
            // The token passed to SendAsync only covers sending the request and
            // receiving the headers; after that it has no effect, so without
            // this a cancelled subscription would sit blocked until the server
            // next sent something -- possibly forever on an idle stream.
            using var registration = cancellationToken.Register(
                static state => ((Stream)state!).Dispose(), stream);

            string? name = null;
            string? id = null;
            var data = new List<string>();

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                string? line;
                try
                {
                    // Not EndOfStream: that property performs a BLOCKING read to
                    // fill its buffer, which on an event stream means occupying
                    // a thread until the next event arrives. A null from
                    // ReadLineAsync is the real end-of-stream signal.
                    line = await reader.ReadLineAsync().ConfigureAwait(false);
                }
                catch (Exception) when (cancellationToken.IsCancellationRequested)
                {
                    // The read failed because the registration above disposed
                    // the stream. That is a cancellation, not a transport fault.
                    throw new OperationCanceledException(cancellationToken);
                }

                if (line is null) break;
                line = line.TrimEnd('\r');

                if (line.Length == 0)
                {
                    if (data.Count > 0)
                    {
                        yield return new LedgerEvent(name, string.Join("\n", data), id);
                        data.Clear();
                        name = null;
                        id = null;
                    }
                    continue;
                }

                if (line.StartsWith(":", StringComparison.Ordinal))
                {
                    // Comment or heartbeat. Ignored deliberately.
                }
                else if (line.StartsWith("event:", StringComparison.Ordinal))
                {
                    name = StripOneSpace(line.Substring("event:".Length));
                }
                else if (line.StartsWith("id:", StringComparison.Ordinal))
                {
                    id = StripOneSpace(line.Substring("id:".Length));
                }
                else if (line.StartsWith("data:", StringComparison.Ordinal))
                {
                    data.Add(StripOneSpace(line.Substring("data:".Length)));
                }
            }

            // A stream ending without a trailing blank line still has a
            // complete event pending.
            if (data.Count > 0)
            {
                yield return new LedgerEvent(name, string.Join("\n", data), id);
            }
        }

        private string RequireCore()
        {
            if (string.IsNullOrEmpty(CoreUrl))
            {
                throw new InvalidOperationException(
                    "No Activecore URL was configured. Event streams are served by " +
                    "Activecore, a separate service from the node - pass coreUrl to " +
                    "the constructor.");
            }
            return CoreUrl!;
        }

        /// <summary>
        /// Subscribes to activity: every stream change on the ledger, or the
        /// changes to one stream when <paramref name="streamId"/> is given.
        /// </summary>
        /// <remarks>
        /// This is the stream that fires for ordinary transactions. Contract
        /// events (<see cref="SubscribeToContractEventsAsync"/>) are a
        /// different feed and only carry what a contract explicitly emitted,
        /// so a subscriber watching there sees nothing for a transaction that
        /// emitted no event -- which looks exactly like a broken subscription.
        /// </remarks>
        public IAsyncEnumerable<LedgerEvent> SubscribeToActivityAsync(
            string? streamId = null, CancellationToken cancellationToken = default)
        {
            var path = streamId is null
                ? "/api/activity/subscribe"
                : $"/api/activity/subscribe/{Uri.EscapeDataString(streamId)}";
            return SubscribeAsync(RequireCore() + path, cancellationToken);
        }

        /// <summary>
        /// Subscribes to events emitted by contracts: all of them, those from
        /// one contract, or one named event from one contract.
        /// </summary>
        public IAsyncEnumerable<LedgerEvent> SubscribeToContractEventsAsync(
            string? contract = null, string? eventName = null,
            CancellationToken cancellationToken = default)
        {
            if (contract is null && eventName is not null)
            {
                throw new ArgumentException(
                    "An event name needs the contract it belongs to", nameof(eventName));
            }

            var path = "/api/events";
            if (contract is not null) path += "/" + Uri.EscapeDataString(contract);
            if (eventName is not null) path += "/" + Uri.EscapeDataString(eventName);
            return SubscribeAsync(RequireCore() + path, cancellationToken);
        }

        /// <summary>
        /// Removes the single optional space after a field's colon.
        /// </summary>
        /// <remarks>
        /// One space, not Trim(). The event-stream format defines exactly one
        /// optional space as framing; every other byte is payload. Trimming
        /// would quietly alter a data field with meaningful leading or trailing
        /// whitespace, and the damage would only show up in whatever consumed
        /// the value later.
        /// </remarks>
        private static string StripOneSpace(string value) =>
            value.Length > 0 && value[0] == ' ' ? value.Substring(1) : value;

        /// <summary>Disposes the HttpClient, but only if this client created it.</summary>
        public void Dispose()
        {
            if (_ownsHttp)
            {
                _http.Dispose();
            }
        }
    }
}
