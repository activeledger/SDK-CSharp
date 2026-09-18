using System;
using System.Collections.Generic;

namespace Activeledger
{
    /// <summary>
    /// A signed transaction, ready to submit.
    /// </summary>
    /// <remarks>
    /// <see cref="Body"/> is the <c>$tx</c> object. <see cref="Sigs"/> maps a
    /// signer label to a base64 signature over the canonical bytes of Body and
    /// NOTHING ELSE -- not the envelope, not a hash of it, not a
    /// length-prefixed form.
    /// </remarks>
    public sealed class Transaction
    {
        private readonly List<string> _sigOrder;

        internal Transaction(JsonObject body, Dictionary<string, string> sigs,
            List<string> sigOrder, bool selfSign)
        {
            Body = body;
            Sigs = sigs;
            _sigOrder = sigOrder;
            SelfSign = selfSign;
        }

        /// <summary>The <c>$tx</c> object. These are the bytes that get signed.</summary>
        public JsonObject Body { get; }

        /// <summary>Base64 signatures, keyed by input stream id (or <c>$i</c> label when onboarding).</summary>
        public IReadOnlyDictionary<string, string> Sigs { get; }

        /// <summary>Whether the envelope carries <c>$selfsign</c>.</summary>
        public bool SelfSign { get; }

        /// <summary>The full envelope, as submitted.</summary>
        public JsonObject Envelope()
        {
            var envelope = new JsonObject().Set("$tx", Body);
            if (SelfSign)
            {
                envelope.Set("$selfsign", true);
            }
            var sigs = new JsonObject();
            foreach (var label in _sigOrder)
            {
                sigs.Set(label, Sigs[label]);
            }
            return envelope.Set("$sigs", sigs);
        }

        /// <summary>The envelope serialised for submission.</summary>
        public string ToJson() => CanonicalJson.Stringify(Envelope());

        /// <summary>
        /// The exact bytes that were signed. The fastest way to diagnose a 1220.
        /// </summary>
        public byte[] SignedBytes() => CanonicalJson.Bytes(Body);

        /// <summary>
        /// Builds the onboarding transaction for a new identity.
        /// </summary>
        /// <remarks>
        /// Two things here are the most common first failure in any port, so
        /// they happen in one place rather than being left to a caller:
        /// <c>$selfsign</c> is true and <c>$sigs</c> is keyed by the <c>$i</c>
        /// LABEL rather than a stream id (there is no stream yet); and
        /// <c>type</c> is always present, because the ledger defaults a missing
        /// one to <c>rsa</c> and then attempts RSA verification against a
        /// base64 post-quantum blob.
        /// </remarks>
        public static Transaction Onboard(ISigner signer, string label = "identity")
        {
            var body = new JsonObject()
                .Set("$namespace", "default")
                .Set("$contract", "onboard")
                .Set("$i", new JsonObject().Set(label, new JsonObject()
                    .Set("type", signer.KeyType.ToWire())
                    .Set("publicKey", signer.PublicKeyBase64)))
                .Set("$o", new JsonObject());

            var signature = Convert.ToBase64String(signer.Sign(CanonicalJson.Bytes(body)));
            return new Transaction(
                body,
                new Dictionary<string, string> { [label] = signature },
                new List<string> { label },
                selfSign: true);
        }

        /// <summary>Starts building an ordinary transaction.</summary>
        public static TransactionBuilder Builder() => new TransactionBuilder();
    }

    /// <summary>
    /// Builds an ordinary transaction.
    /// </summary>
    /// <remarks>
    /// Insertion order is preserved throughout, because the ledger does not
    /// canonicalise key order and the signature covers the order actually
    /// written.
    /// </remarks>
    public sealed class TransactionBuilder
    {
        private string? _namespace;
        private string? _contract;
        private string? _entry;
        private readonly JsonObject _inputs = new JsonObject();
        private readonly JsonObject _outputs = new JsonObject();
        private readonly JsonObject _readonly = new JsonObject();
        private readonly Dictionary<string, ISigner> _signers = new Dictionary<string, ISigner>();
        private readonly List<string> _signOrder = new List<string>();

        /// <summary>Sets <c>$namespace</c>. Required.</summary>
        public TransactionBuilder Namespace(string value) { _namespace = value; return this; }

        /// <summary>Sets <c>$contract</c>. Required.</summary>
        public TransactionBuilder Contract(string value) { _contract = value; return this; }

        /// <summary>Sets <c>$entry</c>, the contract entry point. Omitted when not set.</summary>
        public TransactionBuilder Entry(string value) { _entry = value; return this; }

        /// <summary>Adds an input stream, its signing key and any payload fields.</summary>
        public TransactionBuilder Input(string streamId, ISigner signer, JsonObject? payload = null)
        {
            _inputs.Set(streamId, payload ?? new JsonObject());
            if (!_signers.ContainsKey(streamId))
            {
                _signOrder.Add(streamId);
            }
            _signers[streamId] = signer;
            return this;
        }

        /// <summary>Adds an output stream and any payload fields.</summary>
        public TransactionBuilder Output(string streamId, JsonObject? payload = null)
        {
            _outputs.Set(streamId, payload ?? new JsonObject());
            return this;
        }

        /// <summary>
        /// Adds a stream to <c>$r</c>, the read-only set.
        /// </summary>
        /// <remarks>
        /// This is how state is read from Activeledger. There is no separate
        /// read API: a node's storage service listens only on its own host, so
        /// reading is a transaction like anything else. The contract receives
        /// the named streams and hands values back with <c>returnToRemote</c>,
        /// which arrive in <see cref="LedgerResponse.Responses"/>.
        /// </remarks>
        public TransactionBuilder ReadOnly(string label, string streamId)
        {
            _readonly.Set(label, streamId);
            return this;
        }

        /// <summary>
        /// Signs and returns the transaction. Throws if namespace, contract or
        /// any input is missing.
        /// </summary>
        public Transaction Build()
        {
            if (string.IsNullOrEmpty(_namespace))
                throw new InvalidOperationException("namespace is required");
            if (string.IsNullOrEmpty(_contract))
                throw new InvalidOperationException("contract is required");
            if (_signers.Count == 0)
                throw new InvalidOperationException("at least one input with a signing key is required");

            var body = new JsonObject();
            if (!string.IsNullOrEmpty(_entry))
            {
                body.Set("$entry", _entry!);
            }
            body.Set("$namespace", _namespace!).Set("$contract", _contract!).Set("$i", _inputs);
            if (_outputs.Count > 0) body.Set("$o", _outputs);
            if (_readonly.Count > 0) body.Set("$r", _readonly);

            var message = CanonicalJson.Bytes(body);
            var sigs = new Dictionary<string, string>();
            foreach (var label in _signOrder)
            {
                sigs[label] = Convert.ToBase64String(_signers[label].Sign(message));
            }
            return new Transaction(body, sigs, _signOrder, selfSign: false);
        }
    }
}
