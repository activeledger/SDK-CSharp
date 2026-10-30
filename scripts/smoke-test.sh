#!/usr/bin/env bash
# Smoke test of the PACKED library, the way a consumer gets it.
#
# Packs the SDK into a scratch local feed, builds a throwaway console project
# outside the repo that references only that .nupkg, and runs it: every key
# type, a signed transaction, verification, and submission to a loopback
# server that answers once with a commit and once with a rejection carried in
# an HTTP 200. No external network; restore needs BouncyCastle in the local
# NuGet cache, as any offline build does.
#
# Usage: scripts/smoke-test.sh      (exit 0 and "SMOKE OK" on success)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/activeledger-smoke.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# A unique prerelease version, so a copy of the package left in the global
# NuGet cache by an earlier run can never stand in for the one just packed.
version="0.0.0-smoke.$(date +%s)"
major="$(dotnet --version | cut -d. -f1)"
tfm="${SMOKE_TFM:-net${major}.0}"

echo "== pack $version"
dotnet pack "$repo/src/Activeledger/Activeledger.csproj" -c Release \
  -p:Version="$version" -o "$work/feed" >/dev/null
ls "$work/feed"/Activeledger.SDK."$version".nupkg >/dev/null

mkdir "$work/app"
cat > "$work/app/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$work/feed" />
  </packageSources>
</configuration>
EOF

cat > "$work/app/App.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$tfm</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <InvariantGlobalization>true</InvariantGlobalization>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Activeledger.SDK" Version="$version" />
  </ItemGroup>
</Project>
EOF

cat > "$work/app/Program.cs" <<'CS'
using System.Net;
using System.Net.Sockets;
using System.Text;
using Activeledger;

static void Check(bool ok, string what)
{
    if (!ok) { Console.Error.WriteLine("FAIL: " + what); Environment.Exit(1); }
    Console.WriteLine("ok   " + what);
}

// Proof the code under test is the packed build: only the pack carries this
// unique prerelease version.
var built = typeof(ActiveledgerClient).Assembly
    .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
    .Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion;
Check(built.StartsWith(Environment.GetEnvironmentVariable("SMOKE_VERSION")!, StringComparison.Ordinal),
    "running the packed build " + built);

const string committed = "{\"$summary\":{\"total\":1,\"vote\":1,\"commit\":1,\"errors\":[]},\"$streams\":{\"new\":[{\"id\":\"smoke-stream\"}],\"updated\":[]}}";
const string rejected = "{\"$summary\":{\"total\":1,\"vote\":0,\"commit\":0,\"errors\":[\"Stream(s) not found\"]}}";

var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
var bodies = new List<string>();
var server = Task.Run(async () =>
{
    foreach (var reply in new[] { committed, rejected })
    {
        using var socket = await listener.AcceptTcpClientAsync();
        var stream = socket.GetStream();
        var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int headEnd = -1, want = 0;
        while (true)
        {
            var n = await stream.ReadAsync(chunk);
            if (n == 0) break;
            buffer.Write(chunk, 0, n);
            var text = Encoding.UTF8.GetString(buffer.ToArray());
            if (headEnd < 0)
            {
                headEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headEnd < 0) continue;
                var head = text[..headEnd];
                var at = head.IndexOf("Content-Length:", StringComparison.OrdinalIgnoreCase);
                want = int.Parse(head[(at + 15)..].Split("\r\n")[0].Trim());
            }
            if (buffer.Length >= headEnd + 4 + want) break;
        }
        var all = Encoding.UTF8.GetString(buffer.ToArray());
        bodies.Add(all[(all.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..]);
        var bytes = Encoding.UTF8.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(reply)}\r\nConnection: close\r\n\r\n{reply}");
        await stream.WriteAsync(bytes);
    }
});

var keys = new Dictionary<KeyType, KeyPair>();
foreach (var type in new[] { KeyType.Secp256k1, KeyType.MlDsa65, KeyType.Falcon512 })
{
    var key = KeyPair.Generate(type);
    keys[type] = key;
    Check(key.CanSign && key.PublicKey.Length > 0, "generated " + type.ToWire());

    var tx = Transaction.Builder().Namespace("default").Contract("smoke")
        .Input("sender", key, new JsonObject().Set("amount", 5).Set("note", "héllo"))
        .Output("receiver", new JsonObject()).Build();
    var signature = Convert.FromBase64String(tx.Sigs["sender"]);
    Check(key.Verify(tx.SignedBytes(), signature), "signed and verified " + type.ToWire());

    var tampered = tx.SignedBytes().ToArray();
    tampered[^2] ^= 1;
    Check(!key.Verify(tampered, signature), "tampered bytes fail verification for " + type.ToWire());
}

using var client = new ActiveledgerClient(url);
using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));

var ok = await client.SubmitAsync(Transaction.Onboard(keys[KeyType.MlDsa65]), timeout.Token);
Check(ok.Committed && ok.NewStreams.SequenceEqual(new[] { "smoke-stream" }), "committed reply: committed, new stream id read");

var tx2 = Transaction.Builder().Namespace("default").Contract("smoke").Input("s", keys[KeyType.Secp256k1]).Build();
var bad = await client.SubmitAsync(tx2, timeout.Token);
Check(!bad.Committed && bad.Errors.SequenceEqual(new[] { "Stream(s) not found" }), "rejected HTTP 200 reply: not committed, error surfaced");

await server.WaitAsync(timeout.Token);
Check(bodies.Count == 2 && bodies[1] == tx2.ToJson(), "server received the exact canonical envelope");
Console.WriteLine("SMOKE OK");
CS

echo "== restore, build and run the consumer"
cd "$work/app"
SMOKE_VERSION="$version" dotnet run -c Release
