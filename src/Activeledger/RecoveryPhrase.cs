using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Activeledger
{
    /// <summary>
    /// BIP-39 recovery phrases, and the seed each key type derives from one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There are two layers, and conflating them is the mistake this class is
    /// arranged to prevent. A phrase becomes a 64-byte BIP-39 seed; that seed
    /// becomes the seed the chosen algorithm actually takes. They are
    /// different lengths and different constructions, and
    /// <see cref="DeriveSeed"/> is the step between them.
    /// </para>
    /// <para>
    /// The derivation:
    /// <code>
    /// BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic"+passphrase, 2048, 64)
    ///
    /// ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
    /// falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
    /// secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
    /// </code>
    /// </para>
    /// <para>
    /// secp256k1 does not use HKDF, and that is not an oversight. The
    /// JavaScript SDK has shipped restoreBIP39Key with the construction above
    /// since before the post-quantum types existed, so phrases are already in
    /// use. Changing it would hand every one of those users a different key
    /// for a phrase that used to work - not an error, just an identity that
    /// is no longer theirs. The post-quantum types are new and carry no such
    /// debt, so they get the construction with proper domain separation.
    /// </para>
    /// <para>
    /// BouncyCastle's PBKDF2 and HKDF are used rather than the framework's.
    /// <c>System.Security.Cryptography.HKDF</c> does not exist on
    /// netstandard2.0, and <c>Rfc2898DeriveBytes</c> gained a SHA-512
    /// constructor only later - so the framework route would derive different
    /// keys, or none, depending on which target a consumer built against.
    /// BouncyCastle is already a dependency and behaves identically on both.
    /// </para>
    /// </remarks>
    public static class RecoveryPhrase
    {
        /// <summary>BIP-39's fixed iteration count. Changing it changes every identity.</summary>
        private const int Iterations = 2048;

        /// <summary>A BIP-39 seed is always 64 bytes.</summary>
        public const int Bip39SeedSize = 64;

        private static readonly Lazy<string[]> Wordlist = new Lazy<string[]>(LoadWordlist);

        /// <summary>
        /// The seed length the given key type takes.
        /// </summary>
        /// <remarks>
        /// A wrong length is refused, never padded: a padded seed is a
        /// different identity, not a malformed one.
        /// </remarks>
        public static int SeedSize(KeyType type)
        {
            switch (type)
            {
                case KeyType.Secp256k1:
                case KeyType.MlDsa65:
                    return 32;
                case KeyType.Falcon512:
                    return 48;
                default:
                    throw new NotSupportedException(
                        $"{type.ToWire()} keys cannot be derived from a seed");
            }
        }

        /// <summary>
        /// Checks a phrase and returns it normalised and single-spaced.
        /// </summary>
        /// <remarks>
        /// The checksum is verified, not just word membership. A mistyped
        /// phrase that is not checked does not fail: it derives a perfectly
        /// valid key for an identity nobody owns, and the only symptom is the
        /// ledger not recognising it.
        /// </remarks>
        /// <exception cref="ArgumentException">The phrase is not a valid mnemonic.</exception>
        public static string Validate(string phrase)
        {
            if (phrase == null)
            {
                throw new ArgumentNullException(nameof(phrase));
            }

            var words = phrase.Normalize(NormalizationForm.FormKD)
                .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // 12, 15, 18, 21 and 24 are the only valid lengths.
            if (words.Length < 12 || words.Length > 24 || words.Length % 3 != 0)
            {
                throw new ArgumentException(
                    $"a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got {words.Length}",
                    nameof(phrase));
            }

            var wordlist = Wordlist.Value;
            var index = new Dictionary<string, int>(wordlist.Length, StringComparer.Ordinal);
            for (var i = 0; i < wordlist.Length; i++)
            {
                index[wordlist[i]] = i;
            }

            var bits = new StringBuilder(words.Length * 11);
            for (var position = 0; position < words.Length; position++)
            {
                if (!index.TryGetValue(words[position], out var value))
                {
                    throw new ArgumentException(
                        $"word {position + 1} (\"{words[position]}\") is not in the BIP-39 " +
                        "English wordlist",
                        nameof(phrase));
                }

                bits.Append(Convert.ToString(value, 2).PadLeft(11, '0'));
            }

            var all = bits.ToString();
            var checksumBits = words.Length / 3;
            var entropyBits = all.Length - checksumBits;

            var entropy = new byte[entropyBits / 8];
            for (var i = 0; i < entropy.Length; i++)
            {
                entropy[i] = Convert.ToByte(all.Substring(i * 8, 8), 2);
            }

            var digest = new Sha256Digest();
            var hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(entropy, 0, entropy.Length);
            digest.DoFinal(hash, 0);

            var expected = new StringBuilder(checksumBits);
            for (var bit = 0; bit < checksumBits; bit++)
            {
                expected.Append((hash[0] & (1 << (7 - bit))) != 0 ? '1' : '0');
            }

            if (!string.Equals(all.Substring(entropyBits), expected.ToString(), StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "the BIP-39 checksum does not match - the phrase has a typo or the words " +
                    "are in the wrong order. Deriving from it anyway would produce a valid key " +
                    "for an identity nobody owns.",
                    nameof(phrase));
            }

            return string.Join(" ", words);
        }

        /// <summary>Turns a recovery phrase into its 64-byte BIP-39 seed.</summary>
        /// <exception cref="ArgumentException">The phrase is not a valid mnemonic.</exception>
        public static byte[] ToSeed(string phrase, string passphrase = "")
        {
            var normalised = Validate(phrase);

            var generator = new Pkcs5S2ParametersGenerator(new Sha512Digest());
            generator.Init(
                Encoding.UTF8.GetBytes(normalised),
                // BIP-39's salt: the passphrase is appended to the literal
                // "mnemonic", not passed separately.
                Encoding.UTF8.GetBytes("mnemonic" + (passphrase ?? "").Normalize(NormalizationForm.FormKD)),
                Iterations);

            return ((KeyParameter)generator.GenerateDerivedMacParameters(Bip39SeedSize * 8)).GetKey();
        }

        /// <summary>Turns a BIP-39 seed into the seed the given key type takes.</summary>
        public static byte[] DeriveSeed(KeyType type, byte[] bip39Seed)
        {
            if (bip39Seed == null)
            {
                throw new ArgumentNullException(nameof(bip39Seed));
            }

            if (bip39Seed.Length != Bip39SeedSize)
            {
                throw new ArgumentException(
                    $"a BIP-39 seed is {Bip39SeedSize} bytes, got {bip39Seed.Length}",
                    nameof(bip39Seed));
            }

            var size = SeedSize(type);

            if (type == KeyType.Secp256k1)
            {
                var mac = new HMac(new Sha512Digest());
                mac.Init(new KeyParameter(Encoding.UTF8.GetBytes("Bitcoin seed")));
                mac.BlockUpdate(bip39Seed, 0, bip39Seed.Length);

                var full = new byte[mac.GetMacSize()];
                mac.DoFinal(full, 0);

                var scalar = new byte[32];
                Array.Copy(full, scalar, 32);
                return scalar;
            }

            // A null salt means a block of zero bytes of the hash length,
            // which is what RFC 5869 specifies - checked byte for byte
            // against node's crypto.hkdfSync and PHP's hash_hkdf.
            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(
                bip39Seed,
                null,
                Encoding.UTF8.GetBytes(
                    string.Format(CultureInfo.InvariantCulture, "activeledger-seed-v1:{0}", type.ToWire()))));

            var seed = new byte[size];
            hkdf.GenerateBytes(seed, 0, size);
            return seed;
        }

        private static string[] LoadWordlist()
        {
            var assembly = typeof(RecoveryPhrase).GetTypeInfo().Assembly;
            var name = Array.Find(
                assembly.GetManifestResourceNames(),
                candidate => candidate.EndsWith("bip39-english.txt", StringComparison.Ordinal));

            if (name == null)
            {
                throw new InvalidOperationException(
                    "The BIP-39 wordlist is not embedded in this assembly");
            }

            using (var stream = assembly.GetManifestResourceStream(name))
            using (var reader = new StreamReader(stream!, Encoding.UTF8))
            {
                var words = reader.ReadToEnd()
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                if (words.Length != 2048)
                {
                    throw new InvalidOperationException(
                        $"The BIP-39 wordlist should hold 2048 words, found {words.Length}");
                }

                return words;
            }
        }
    }
}
