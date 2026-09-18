using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Activeledger
{
    /// <summary>
    /// A JSON value the canonical serialiser can write.
    /// </summary>
    public interface IJsonValue
    {
    }

    /// <summary>
    /// A JSON object that preserves insertion order.
    /// </summary>
    /// <remarks>
    /// Order matters and is not a stylistic choice. Activeledger signs the exact
    /// bytes of <c>JSON.stringify($tx)</c> and does not canonicalise key order,
    /// so a signer must reproduce the order the caller wrote. A
    /// <see cref="Dictionary{TKey,TValue}"/> gives no such guarantee, and
    /// <c>System.Text.Json</c> offers no ordering control for one.
    /// </remarks>
    public sealed class JsonObject : IJsonValue
    {
        private readonly List<string> _keys = new List<string>();
        private readonly Dictionary<string, IJsonValue?> _values = new Dictionary<string, IJsonValue?>();

        /// <summary>Adds or replaces a key. A replaced key keeps its position.</summary>
        public JsonObject Set(string key, IJsonValue? value)
        {
            if (!_values.ContainsKey(key))
            {
                _keys.Add(key);
            }
            _values[key] = value;
            return this;
        }

        /// <summary>Adds or replaces a string value.</summary>
        public JsonObject Set(string key, string value) => Set(key, new JsonString(value));

        /// <summary>Adds or replaces an integer value.</summary>
        public JsonObject Set(string key, long value) => Set(key, new JsonNumber(value));

        /// <summary>Adds or replaces a numeric value.</summary>
        public JsonObject Set(string key, double value) => Set(key, new JsonNumber(value));

        /// <summary>Adds or replaces a boolean value.</summary>
        public JsonObject Set(string key, bool value) => Set(key, new JsonBool(value));

        /// <summary>Adds or replaces a key whose value is JSON null.</summary>
        public JsonObject SetNull(string key) => Set(key, (IJsonValue?)null);

        /// <summary>The value at a key, or null if absent.</summary>
        public IJsonValue? Get(string key) =>
            _values.TryGetValue(key, out var value) ? value : null;

        /// <summary>Whether the key is present.</summary>
        public bool Has(string key) => _values.ContainsKey(key);

        /// <summary>Keys in insertion order.</summary>
        public IReadOnlyList<string> Keys => _keys;

        /// <summary>The number of keys.</summary>
        public int Count => _keys.Count;

        internal IEnumerable<KeyValuePair<string, IJsonValue?>> Entries()
        {
            foreach (var key in _keys)
            {
                yield return new KeyValuePair<string, IJsonValue?>(key, _values[key]);
            }
        }
    }

    /// <summary>A JSON array.</summary>
    public sealed class JsonArray : IJsonValue
    {
        private readonly List<IJsonValue?> _items = new List<IJsonValue?>();

        /// <summary>Appends a value.</summary>
        public JsonArray Add(IJsonValue? value)
        {
            _items.Add(value);
            return this;
        }

        /// <summary>Appends a string.</summary>
        public JsonArray Add(string value) => Add(new JsonString(value));

        /// <summary>Appends an integer.</summary>
        public JsonArray Add(long value) => Add(new JsonNumber(value));

        /// <summary>Appends a number.</summary>
        public JsonArray Add(double value) => Add(new JsonNumber(value));

        /// <summary>Appends a boolean.</summary>
        public JsonArray Add(bool value) => Add(new JsonBool(value));

        /// <summary>Appends a JSON null.</summary>
        public JsonArray AddNull() => Add((IJsonValue?)null);

        /// <summary>The number of items.</summary>
        public int Count => _items.Count;

        internal IReadOnlyList<IJsonValue?> Items => _items;
    }

    /// <summary>A JSON string.</summary>
    public sealed class JsonString : IJsonValue
    {
        /// <summary>Wraps a string value.</summary>
        public JsonString(string value) => Value = value;

        /// <summary>The value.</summary>
        public string Value { get; }
    }

    /// <summary>
    /// A JSON number. One numeric type, as in JavaScript, so that whole values
    /// serialise the way <c>JSON.stringify</c> writes them.
    /// </summary>
    public sealed class JsonNumber : IJsonValue
    {
        /// <summary>Wraps a numeric value.</summary>
        public JsonNumber(double value) => Value = value;

        /// <summary>The value.</summary>
        public double Value { get; }
    }

    /// <summary>A JSON boolean.</summary>
    public sealed class JsonBool : IJsonValue
    {
        /// <summary>Wraps a boolean value.</summary>
        public JsonBool(bool value) => Value = value;

        /// <summary>The value.</summary>
        public bool Value { get; }
    }

    /// <summary>
    /// Serialises exactly as JavaScript's <c>JSON.stringify</c> does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Signatures cover the exact bytes of <c>JSON.stringify($tx)</c> encoded
    /// UTF-8 -- no hash prefix, no length prefix, no domain separator, no key
    /// sorting. A signature over bytes differing by one escape is invalid, and
    /// the ledger reports it as 1220 "Signature Incorrect", which says nothing
    /// about serialisation.
    /// </para>
    /// <para>
    /// Written by hand rather than configured, because
    /// <c>System.Text.Json</c> escapes non-ASCII and HTML-sensitive characters
    /// by default and offers no insertion-order guarantee for a dictionary.
    /// Both defects produce correct output on an ASCII-only payload with one
    /// key, which is why they are worth owning.
    /// </para>
    /// </remarks>
    public static class CanonicalJson
    {
        /// <summary>Serialises to the exact string the ledger expects.</summary>
        public static string Stringify(IJsonValue? value)
        {
            var sb = new StringBuilder();
            Write(sb, value);
            return sb.ToString();
        }

        /// <summary>The exact bytes that get signed.</summary>
        public static byte[] Bytes(IJsonValue? value) =>
            new UTF8Encoding(false).GetBytes(Stringify(value));

        private static void Write(StringBuilder sb, IJsonValue? value)
        {
            switch (value)
            {
                case null:
                    sb.Append("null");
                    break;
                case JsonObject obj:
                {
                    sb.Append('{');
                    var first = true;
                    foreach (var entry in obj.Entries())
                    {
                        if (!first) sb.Append(',');
                        first = false;
                        WriteString(sb, entry.Key);
                        sb.Append(':');
                        Write(sb, entry.Value);
                    }
                    sb.Append('}');
                    break;
                }
                case JsonArray array:
                {
                    sb.Append('[');
                    for (var i = 0; i < array.Items.Count; i++)
                    {
                        if (i > 0) sb.Append(',');
                        Write(sb, array.Items[i]);
                    }
                    sb.Append(']');
                    break;
                }
                case JsonString str:
                    WriteString(sb, str.Value);
                    break;
                case JsonNumber number:
                    WriteNumber(sb, number.Value);
                    break;
                case JsonBool boolean:
                    sb.Append(boolean.Value ? "true" : "false");
                    break;
                default:
                    throw new ArgumentException(
                        $"Unsupported value type {value.GetType().Name}. Build a JsonObject " +
                        "explicitly rather than relying on reflection - what gets signed is " +
                        "these exact bytes, so an inferred conversion would be a silent risk.");
            }
        }

        /// <summary>
        /// JavaScript number formatting: one numeric type, shortest
        /// round-tripping representation. <c>JSON.stringify(1.0)</c> is "1".
        /// </summary>
        private static void WriteNumber(StringBuilder sb, double value)
        {
            // JSON.stringify emits null for these, which would sign bytes the
            // caller never intended. Refuse instead.
            if (double.IsNaN(value))
                throw new ArgumentException("NaN cannot be signed");
            if (double.IsInfinity(value))
                throw new ArgumentException("Infinity cannot be signed");

            if (value == Math.Truncate(value) && Math.Abs(value) < 1e21)
            {
                // InvariantCulture throughout: a machine running under a locale
                // that uses a comma as the decimal separator would otherwise
                // produce "1,5" and sign bytes no ledger can read. This is the
                // kind of bug that only appears on someone else's machine.
                sb.Append(((long)value).ToString(CultureInfo.InvariantCulture));
                return;
            }
            sb.Append(value.ToString("R", CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Escapes exactly what JSON.stringify escapes: the two characters JSON
        /// requires plus control characters below 0x20. Everything else --
        /// including all non-ASCII -- passes through as raw UTF-8.
        /// </summary>
        private static void WriteString(StringBuilder sb, string value)
        {
            sb.Append('"');
            foreach (var c in value)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < ' ')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
