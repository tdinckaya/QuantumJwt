using System.Security.Cryptography;

namespace QuantumJwt;

/// <summary>
/// Algorithm identifiers for ML-DSA and Composite ML-DSA used in JWT headers.
/// </summary>
public static class MlDsaAlgorithms
{
    // ── Pure ML-DSA ──────────────────────────────────────────────

    /// <summary>ML-DSA-44 (FIPS 204, security level 2).</summary>
    public const string MlDsa44 = "ML-DSA-44";

    /// <summary>ML-DSA-65 (FIPS 204, security level 3 — recommended).</summary>
    public const string MlDsa65 = "ML-DSA-65";

    /// <summary>ML-DSA-87 (FIPS 204, security level 5).</summary>
    public const string MlDsa87 = "ML-DSA-87";

    // ── Composite ML-DSA ─────────────────────────────────────────

    /// <summary>ML-DSA-44 + ECDSA P-256.</summary>
    public const string MlDsa44WithECDsaP256 = "MLDSA44-ECDSA-P256";

    /// <summary>ML-DSA-44 + RSA-2048 PSS.</summary>
    public const string MlDsa44WithRSA2048Pss = "MLDSA44-RSA2048-PSS";

    /// <summary>ML-DSA-44 + Ed25519.</summary>
    public const string MlDsa44WithEd25519 = "MLDSA44-Ed25519";

    /// <summary>ML-DSA-65 + ECDSA P-256.</summary>
    public const string MlDsa65WithECDsaP256 = "MLDSA65-ECDSA-P256";

    /// <summary>ML-DSA-65 + ECDSA P-384.</summary>
    public const string MlDsa65WithECDsaP384 = "MLDSA65-ECDSA-P384";

    /// <summary>ML-DSA-65 + RSA-3072 PSS.</summary>
    public const string MlDsa65WithRSA3072Pss = "MLDSA65-RSA3072-PSS";

    /// <summary>ML-DSA-65 + RSA-4096 PSS.</summary>
    public const string MlDsa65WithRSA4096Pss = "MLDSA65-RSA4096-PSS";

    /// <summary>ML-DSA-65 + Ed25519.</summary>
    public const string MlDsa65WithEd25519 = "MLDSA65-Ed25519";

    /// <summary>ML-DSA-87 + ECDSA P-384.</summary>
    public const string MlDsa87WithECDsaP384 = "MLDSA87-ECDSA-P384";

    /// <summary>ML-DSA-87 + ECDSA P-521.</summary>
    public const string MlDsa87WithECDsaP521 = "MLDSA87-ECDSA-P521";

    /// <summary>ML-DSA-87 + RSA-4096 PSS.</summary>
    public const string MlDsa87WithRSA4096Pss = "MLDSA87-RSA4096-PSS";

    /// <summary>ML-DSA-87 + Ed448.</summary>
    public const string MlDsa87WithEd448 = "MLDSA87-Ed448";

    // ── Lookup sets ──────────────────────────────────────────────

    /// <summary>All supported pure ML-DSA algorithm identifiers.</summary>
    internal static readonly HashSet<string> Pure = new(StringComparer.OrdinalIgnoreCase)
    {
        MlDsa44, MlDsa65, MlDsa87
    };

    /// <summary>All supported composite ML-DSA algorithm identifiers.</summary>
    internal static readonly HashSet<string> Composite = new(StringComparer.OrdinalIgnoreCase)
    {
        MlDsa44WithECDsaP256, MlDsa44WithRSA2048Pss, MlDsa44WithEd25519,
        MlDsa65WithECDsaP256, MlDsa65WithECDsaP384, MlDsa65WithRSA3072Pss,
        MlDsa65WithRSA4096Pss, MlDsa65WithEd25519,
        MlDsa87WithECDsaP384, MlDsa87WithECDsaP521, MlDsa87WithRSA4096Pss,
        MlDsa87WithEd448
    };

    /// <summary>All supported algorithm identifiers (pure + composite).</summary>
    internal static readonly HashSet<string> All = new(Pure.Concat(Composite), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps a pure ML-DSA algorithm string to its <see cref="MLDsaAlgorithm"/> instance.
    /// </summary>
    internal static MLDsaAlgorithm ToMLDsaAlgorithm(string algorithm) => algorithm.ToUpperInvariant() switch
    {
        "ML-DSA-44" => MLDsaAlgorithm.MLDsa44,
        "ML-DSA-65" => MLDsaAlgorithm.MLDsa65,
        "ML-DSA-87" => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentException($"Unsupported pure ML-DSA algorithm: {algorithm}", nameof(algorithm))
    };

    /// <summary>
    /// Maps a composite ML-DSA algorithm string to its <see cref="CompositeMLDsaAlgorithm"/> instance.
    /// </summary>
    internal static CompositeMLDsaAlgorithm ToCompositeMLDsaAlgorithm(string algorithm) => algorithm.ToUpperInvariant() switch
    {
        "MLDSA44-ECDSA-P256" => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
        "MLDSA44-RSA2048-PSS" => CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss,
        "MLDSA44-ED25519" => CompositeMLDsaAlgorithm.MLDsa44WithEd25519,
        "MLDSA65-ECDSA-P256" => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
        "MLDSA65-ECDSA-P384" => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384,
        "MLDSA65-RSA3072-PSS" => CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss,
        "MLDSA65-RSA4096-PSS" => CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss,
        "MLDSA65-ED25519" => CompositeMLDsaAlgorithm.MLDsa65WithEd25519,
        "MLDSA87-ECDSA-P384" => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
        "MLDSA87-ECDSA-P521" => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521,
        "MLDSA87-RSA4096-PSS" => CompositeMLDsaAlgorithm.MLDsa87WithRSA4096Pss,
        "MLDSA87-ED448" => CompositeMLDsaAlgorithm.MLDsa87WithEd448,
        _ => throw new ArgumentException($"Unsupported composite ML-DSA algorithm: {algorithm}", nameof(algorithm))
    };

    /// <summary>
    /// Returns the JWT algorithm identifier string for a given <see cref="MLDsaAlgorithm"/>.
    /// </summary>
    internal static string ToJwtAlgorithm(MLDsaAlgorithm algorithm)
    {
        if (algorithm == MLDsaAlgorithm.MLDsa44) return MlDsa44;
        if (algorithm == MLDsaAlgorithm.MLDsa65) return MlDsa65;
        if (algorithm == MLDsaAlgorithm.MLDsa87) return MlDsa87;
        throw new ArgumentException($"Unknown MLDsaAlgorithm: {algorithm.Name}", nameof(algorithm));
    }

    /// <summary>
    /// Returns the JWT algorithm identifier string for a given <see cref="CompositeMLDsaAlgorithm"/>.
    /// </summary>
    internal static string ToJwtAlgorithm(CompositeMLDsaAlgorithm algorithm)
    {
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256) return MlDsa44WithECDsaP256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss) return MlDsa44WithRSA2048Pss;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithEd25519) return MlDsa44WithEd25519;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256) return MlDsa65WithECDsaP256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384) return MlDsa65WithECDsaP384;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss) return MlDsa65WithRSA3072Pss;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss) return MlDsa65WithRSA4096Pss;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithEd25519) return MlDsa65WithEd25519;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384) return MlDsa87WithECDsaP384;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521) return MlDsa87WithECDsaP521;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithRSA4096Pss) return MlDsa87WithRSA4096Pss;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithEd448) return MlDsa87WithEd448;
        throw new ArgumentException($"Unknown CompositeMLDsaAlgorithm: {algorithm.Name}", nameof(algorithm));
    }
}
