using System;

namespace Activeledger
{
    /// <summary>
    /// Key algorithms, with the exact strings the ledger uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These strings are the whole contract: the ledger validates nothing else
    /// about them. A typo, or a key of the wrong length, surfaces as 1220
    /// "Signature Incorrect" and never as "unknown algorithm".
    /// </para>
    /// <para>
    /// The ledger also DEFAULTS a missing type to <c>rsa</c> and then attempts
    /// RSA verification against whatever it was given, so this SDK always sends
    /// the type explicitly and never relies on a default.
    /// </para>
    /// </remarks>
    public enum KeyType
    {
        /// <summary>RSA, the ledger's original scheme. Wire string <c>rsa</c>.</summary>
        Rsa,

        /// <summary>secp256k1 elliptic curve. Wire string <c>secp256k1</c>.</summary>
        Secp256k1,

        /// <summary>ML-DSA-65 (FIPS 204). Post-quantum. Wire string <c>ml-dsa-65</c>.</summary>
        MlDsa65,

        /// <summary>Falcon-512. Post-quantum. Wire string <c>falcon-512</c>.</summary>
        Falcon512,
    }

    /// <summary>Converts between <see cref="KeyType"/> and its wire string.</summary>
    public static class KeyTypes
    {
        /// <summary>The exact string the ledger expects for this key type.</summary>
        public static string ToWire(this KeyType type) => type switch
        {
            KeyType.Rsa => "rsa",
            KeyType.Secp256k1 => "secp256k1",
            KeyType.MlDsa65 => "ml-dsa-65",
            KeyType.Falcon512 => "falcon-512",
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };

        /// <summary>
        /// Parses a wire string, throwing on anything unrecognised.
        /// </summary>
        /// <remarks>
        /// Deliberately strict and case-sensitive: the ledger compares these
        /// exactly, so accepting "ML-DSA-65" here would only move the failure
        /// somewhere less informative.
        /// </remarks>
        public static KeyType FromWire(string wire) => wire switch
        {
            "rsa" => KeyType.Rsa,
            "secp256k1" => KeyType.Secp256k1,
            "ml-dsa-65" => KeyType.MlDsa65,
            "falcon-512" => KeyType.Falcon512,
            _ => throw new ArgumentException(
                $"Unknown key type '{wire}' - expected rsa, secp256k1, ml-dsa-65 or falcon-512"),
        };

        /// <summary>True for <see cref="KeyType.MlDsa65"/> and <see cref="KeyType.Falcon512"/>.</summary>
        public static bool IsPostQuantum(this KeyType type) =>
            type == KeyType.MlDsa65 || type == KeyType.Falcon512;
    }

    /// <summary>
    /// Anything that can sign transaction bytes and name its key type.
    /// </summary>
    /// <remarks>
    /// An interface rather than a concrete type so a caller can sign elsewhere
    /// -- an HSM, a remote signing service, a key in a user's wallet -- without
    /// this SDK needing to know about it.
    /// </remarks>
    public interface ISigner
    {
        /// <summary>The algorithm this signer uses.</summary>
        KeyType KeyType { get; }

        /// <summary>The public key, base64, in the encoding the ledger stores.</summary>
        string PublicKeyBase64 { get; }

        /// <summary>
        /// Signs the canonical bytes of a <c>$tx</c> object, returning the raw
        /// signature. The caller base64-encodes it for <c>$sigs</c>.
        /// </summary>
        byte[] Sign(byte[] message);
    }
}
