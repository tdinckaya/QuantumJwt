using System.Security.Cryptography;

namespace QuantumDataProtection;

/// <summary>
/// Algorithm identifiers for ML-KEM (FIPS 203) key encapsulation.
/// </summary>
public static class MlKemAlgorithms
{
    /// <summary>ML-KEM-512 (FIPS 203, security level 1).</summary>
    public const string MlKem512 = "ML-KEM-512";

    /// <summary>ML-KEM-768 (FIPS 203, security level 3 — recommended).</summary>
    public const string MlKem768 = "ML-KEM-768";

    /// <summary>ML-KEM-1024 (FIPS 203, security level 5).</summary>
    public const string MlKem1024 = "ML-KEM-1024";

    internal static readonly HashSet<string> All = new(StringComparer.OrdinalIgnoreCase)
    {
        MlKem512, MlKem768, MlKem1024
    };

    /// <summary>
    /// Maps an algorithm string to its <see cref="MLKemAlgorithm"/> instance.
    /// </summary>
    internal static MLKemAlgorithm ToMLKemAlgorithm(string algorithm) => algorithm.ToUpperInvariant() switch
    {
        "ML-KEM-512" => MLKemAlgorithm.MLKem512,
        "ML-KEM-768" => MLKemAlgorithm.MLKem768,
        "ML-KEM-1024" => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentException($"Unsupported ML-KEM algorithm: {algorithm}", nameof(algorithm))
    };

    /// <summary>
    /// Returns the string identifier for a given <see cref="MLKemAlgorithm"/>.
    /// </summary>
    internal static string ToAlgorithmString(MLKemAlgorithm algorithm)
    {
        if (algorithm == MLKemAlgorithm.MLKem512) return MlKem512;
        if (algorithm == MLKemAlgorithm.MLKem768) return MlKem768;
        if (algorithm == MLKemAlgorithm.MLKem1024) return MlKem1024;
        throw new ArgumentException($"Unknown MLKemAlgorithm: {algorithm.Name}", nameof(algorithm));
    }
}
