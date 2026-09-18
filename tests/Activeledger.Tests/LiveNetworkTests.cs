using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Activeledger;
using Xunit;

namespace Activeledger.Tests
{
    /// <summary>
    /// A Fact that skips itself unless a live network is configured.
    /// </summary>
    /// <remarks>
    /// A real skip, not an early return. A test that quietly returns green
    /// when the ledger is absent reports coverage nobody has.
    /// </remarks>
    public sealed class LiveFactAttribute : FactAttribute
    {
        public LiveFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(LiveNetwork.NodesRaw))
            {
                Skip = "AL_NODES not set - start 'npm run test:network:serve' in the ledger repo";
            }
        }
    }

    internal static class LiveNetwork
    {
        public static string? NodesRaw => Environment.GetEnvironmentVariable("AL_NODES");
        public static string? StorageRaw => Environment.GetEnvironmentVariable("AL_STORAGE");

        public static IReadOnlyList<string> Nodes =>
            (NodesRaw ?? "").Split(',').Where(s => s.Length > 0).ToList();

        public static IReadOnlyList<string> Storage =>
            (StorageRaw ?? "").Split(',').Where(s => s.Length > 0).ToList();
    }

    /// <summary>
    /// Runs against a real 4-node Activeledger network.
    ///
    /// Every other test here checks this SDK against a published file. This one
    /// checks it against a running ledger, which is the only thing that
    /// actually decides whether a signature is acceptable -- the type string,
    /// the $sigs keying and the exact signed bytes are all invisible to a unit
    /// test, and all three fail as the same unhelpful 1220.
    ///
    /// Start the network from an activeledger checkout:
    ///
    ///     npm run test:network:serve
    ///
    /// then run with the URLs it prints:
    ///
    ///     AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 dotnet test
    /// </summary>
    [Collection("live")]
    public class LiveNetworkTests
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        private static ActiveledgerClient Client(int index = 0) =>
            new ActiveledgerClient(LiveNetwork.Nodes[index], Http);

        // Namespaces are claimed permanently, so a fixed name passes once and
        // fails every re-run against the same network -- which reads exactly
        // like a regression and is not one.
        private static string Unique(string prefix) =>
            prefix + DateTime.UtcNow.Ticks % 100000000;

        /// <summary>
        /// Reads a document straight from a node's storage service.
        /// </summary>
        /// <remarks>
        /// Deliberately in the test and NOT in the SDK: storage listens only on
        /// the node's own host, so a real client cannot reach it and reads
        /// state through a transaction's <c>$r</c> instead. This harness runs
        /// locally, where storage is reachable by definition, and it is used
        /// here to assert what the ledger RECORDED rather than what a contract
        /// chose to report.
        /// </remarks>
        private static async Task<JsonElement> StorageRead(int index, string id)
        {
            Assert.True(LiveNetwork.Storage.Count > index,
                "AL_STORAGE not set - cannot verify what the ledger recorded");

            var url = $"{LiveNetwork.Storage[index].TrimEnd('/')}/activeledger/{Uri.EscapeDataString(id)}";
            var raw = await Http.GetStringAsync(url);
            return JsonDocument.Parse(raw).RootElement.Clone();
        }

        /// <summary>
        /// Waits for a stream's metadata to appear.
        /// </summary>
        /// <remarks>
        /// Consensus is a majority, so the origin's reply means MOST nodes have
        /// committed -- the rest may still be writing. Reading immediately is a
        /// race that fails a few percent of the time and looks like flakiness
        /// in the SDK.
        /// </remarks>
        private static async Task<JsonElement> AwaitAuthorities(int node, string streamId)
        {
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    var meta = await StorageRead(node, streamId + ":stream");
                    if (meta.TryGetProperty("authorities", out var authorities) &&
                        authorities.ValueKind == JsonValueKind.Array &&
                        authorities.GetArrayLength() > 0)
                    {
                        return authorities;
                    }
                }
                catch (HttpRequestException)
                {
                    // Not written yet on this node.
                }
                await Task.Delay(500);
            }

            throw new Xunit.Sdk.XunitException($"stream meta for {streamId} never appeared on node {node}");
        }

        [LiveFact]
        public Task MlDsaIdentityOnboardsAndIsRecordedCorrectly() =>
            OnboardAndCheck(KeyType.MlDsa65, 1952);

        [LiveFact]
        public Task FalconIdentityOnboardsAndIsRecordedCorrectly() =>
            OnboardAndCheck(KeyType.Falcon512, 897);

        private static async Task OnboardAndCheck(KeyType type, int expectedPublicBytes)
        {
            var key = KeyPair.Generate(type);
            var identity = await Client().OnboardAsync(key);
            Assert.NotEmpty(identity.StreamId);

            var authority = (await AwaitAuthorities(0, identity.StreamId))[0];

            // The type the LEDGER stored. If this is "rsa", the SDK omitted it
            // and every later signature would fail verification.
            Assert.Equal(type.ToWire(), authority.GetProperty("type").GetString());

            var stored = Convert.FromBase64String(authority.GetProperty("public").GetString()!);
            Assert.Equal(expectedPublicBytes, stored.Length);
            Assert.Equal(key.PublicKeyBase64, authority.GetProperty("public").GetString());
        }

        [LiveFact]
        public async Task ATransactionSignedByThisSdkIsAccepted()
        {
            var client = Client();
            var identity = await client.OnboardAsync(KeyPair.Generate(KeyType.MlDsa65));

            var tx = Transaction.Builder()
                .Namespace("default").Contract("namespace")
                .Input(identity.StreamId, identity.Signer,
                    new JsonObject().Set("namespace", Unique("csharp")))
                .Build();

            var response = await client.SubmitAsync(tx);
            Assert.True(response.Committed, $"rejected: {response.Raw}");
        }

        [LiveFact]
        public async Task AFalconSignedTransactionIsAccepted()
        {
            var client = Client();
            var identity = await client.OnboardAsync(KeyPair.Generate(KeyType.Falcon512));

            var tx = Transaction.Builder()
                .Namespace("default").Contract("namespace")
                .Input(identity.StreamId, identity.Signer,
                    new JsonObject().Set("namespace", Unique("csfalcon")))
                .Build();

            var response = await client.SubmitAsync(tx);
            Assert.True(response.Committed, $"rejected: {response.Raw}");
        }

        // Without this the suite would pass against a ledger that accepted
        // everything, which would make every test above meaningless.
        [LiveFact]
        public async Task ATamperedPayloadIsRejected()
        {
            var client = Client();
            var identity = await client.OnboardAsync(KeyPair.Generate(KeyType.MlDsa65));

            var honest = Transaction.Builder()
                .Namespace("default").Contract("namespace")
                .Input(identity.StreamId, identity.Signer,
                    new JsonObject().Set("namespace", Unique("cstamper")))
                .Build();

            // Same signature, different body. Submitted raw because the builder
            // would re-sign it back into a valid transaction.
            var tampered = honest.ToJson().Replace("cstamper", "csstolen");

            var response = await client.SubmitRawAsync(tampered);
            Assert.False(response.Committed, $"a tampered payload was accepted: {response.Raw}");
        }

        [LiveFact]
        public async Task AnIdentityOnboardedHereIsVisibleFromEveryNode()
        {
            var identity = await Client().OnboardAsync(KeyPair.Generate(KeyType.MlDsa65));

            for (var node = 0; node < LiveNetwork.Storage.Count; node++)
            {
                var authorities = await AwaitAuthorities(node, identity.StreamId);
                Assert.Equal("ml-dsa-65", authorities[0].GetProperty("type").GetString());
            }
        }

        // SSE against a real Activeledger event stream.
        //
        // Aimed at the storage engine's /activeledgerevents/events, because
        // that is what this harness runs: Activecore, which serves the
        // remote-facing /api/activity and /api/events feeds, is a separate
        // service and is not started here. Storage listens only on the node's
        // own host, so this is NOT how a real client subscribes -- but it is a
        // genuine ledger SSE endpoint, and it is the only one available to
        // assert against.
        //
        // What this proves, and the stub tests cannot: the request headers are
        // acceptable to a real server, the response is not rejected, and the
        // connection is held open rather than closed immediately.
        //
        // What it deliberately does NOT assert is event DELIVERY. Events exist
        // only when a contract emits one, so observing a payload would mean
        // deploying an emitting contract from here. The ledger's own network
        // harness already covers delivery across all four nodes; duplicating
        // it here would test the ledger rather than this SDK.
        [LiveFact]
        public async Task SubscribingToARealNodeOpensAndHoldsTheStream()
        {
            Assert.NotEmpty(LiveNetwork.Storage);
            var endpoint = $"{LiveNetwork.Storage[0].TrimEnd('/')}/activeledgerevents/events";

            using var client = Client();
            using var cts = new CancellationTokenSource();

            var subscription = Task.Run(async () =>
            {
                await foreach (var _ in client.SubscribeAsync(endpoint, cts.Token))
                {
                }
            });

            // A refused or immediately-closed stream ends within milliseconds.
            var ended = await Task.WhenAny(subscription, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.True(ended != subscription,
                $"the stream ended on its own: {subscription.Exception?.GetBaseException().Message}");

            // Cancelling must actually close it. This is the one place that
            // exercises cancellation against a real socket: the read is
            // interrupted by disposing the stream, and nothing in a stub test
            // can show that works, because a MemoryStream never blocks.
            cts.Cancel();
            var closed = await Task.WhenAny(subscription, Task.Delay(TimeSpan.FromSeconds(10)));
            Assert.True(closed == subscription, "cancelling did not close the subscription");
        }

        // Pointing a subscription at the node rather than Activecore is the
        // easy mistake, and the node's answer (403) must surface as an error
        // rather than as a stream that never produces anything.
        [LiveFact]
        public async Task SubscribingToTheNodePortIsReportedAsAnError()
        {
            using var client = Client();

            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.SubscribeAsync("/api/events").ToListAsync());
        }

    }
}
