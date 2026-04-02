using System.Security.Cryptography;
using QuantumJwt;

namespace QuantumDataProtection;

/// <summary>
/// Configuration options for ML-KEM based Data Protection key wrapping.
/// </summary>
public sealed class MlKemDataProtectionOptions
{
    /// <summary>
    /// The ML-KEM algorithm variant. Defaults to ML-KEM-768 (recommended).
    /// </summary>
    public MLKemAlgorithm Algorithm { get; set; } = MLKemAlgorithm.MLKem768;

    /// <summary>
    /// Custom <see cref="IKeyStore"/> for storing decapsulation keys.
    /// If set, <see cref="KeyStoreDirectory"/> and <see cref="KeyStorePassword"/> are ignored.
    /// </summary>
    public IKeyStore? KeyStore { get; set; }

    /// <summary>
    /// Directory for the built-in <see cref="FileKeyStore"/>.
    /// Used only if <see cref="KeyStore"/> is null.
    /// </summary>
    public string? KeyStoreDirectory { get; set; }

    /// <summary>
    /// Password for the built-in <see cref="FileKeyStore"/>.
    /// Used only if <see cref="KeyStore"/> is null.
    /// </summary>
    public string? KeyStorePassword { get; set; }

    /// <summary>
    /// Resolves the <see cref="IKeyStore"/> from the configured options.
    /// </summary>
    internal IKeyStore ResolveKeyStore()
    {
        if (KeyStore is not null)
            return KeyStore;

        if (string.IsNullOrEmpty(KeyStoreDirectory) || string.IsNullOrEmpty(KeyStorePassword))
            throw new InvalidOperationException(
                "Either set KeyStore directly, or provide both KeyStoreDirectory and KeyStorePassword.");

        return new FileKeyStore(KeyStoreDirectory, KeyStorePassword);
    }
}
