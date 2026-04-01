using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// A <see cref="SecurityKey"/> that wraps a .NET 10 <see cref="MLDsa"/> instance
/// for use with the Microsoft.IdentityModel.Tokens JWT pipeline.
/// <para>
/// Drop-in replacement for <see cref="RsaSecurityKey"/>:
/// <code>
/// options.TokenValidationParameters = new()
/// {
///     IssuerSigningKey = new MlDsaSecurityKey(mlDsaKey)
/// };
/// </code>
/// </para>
/// </summary>
public sealed class MlDsaSecurityKey : AsymmetricSecurityKey, IDisposable
{
    private readonly bool _ownsKey;
    private readonly bool _hasPrivateKey;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance wrapping an existing <see cref="MLDsa"/> key.
    /// The <see cref="SecurityKey.CryptoProviderFactory"/> is automatically configured.
    /// </summary>
    /// <param name="mlDsa">The ML-DSA key instance to wrap.</param>
    /// <param name="ownsKey">
    /// If <c>true</c> (default), the underlying <paramref name="mlDsa"/> will be
    /// disposed when this key is disposed.
    /// </param>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when the current platform does not support ML-DSA
    /// (requires Windows 11/Server 2025 or Linux with OpenSSL 3.5+).
    /// </exception>
    public MlDsaSecurityKey(MLDsa mlDsa, bool ownsKey = true)
    {
        ThrowIfPlatformUnsupported();

        MlDsa = mlDsa ?? throw new ArgumentNullException(nameof(mlDsa));
        Algorithm = mlDsa.Algorithm;
        _ownsKey = ownsKey;

        // Determine private key availability
        _hasPrivateKey = TryDetectPrivateKey(mlDsa);

        // Auto-configure CryptoProviderFactory so the JWT pipeline
        // knows how to create signature providers for this key
        CryptoProviderFactory = new CryptoProviderFactory
        {
            CustomCryptoProvider = new MlDsaCryptoProvider()
        };

        // Generate a deterministic KeyId from the public key hash
        KeyId = GenerateKeyId(mlDsa);
    }

    /// <summary>The underlying <see cref="MLDsa"/> instance.</summary>
    public MLDsa MlDsa { get; }

    /// <summary>The ML-DSA algorithm variant (MLDsa44, MLDsa65, or MLDsa87).</summary>
    public MLDsaAlgorithm Algorithm { get; }

    /// <inheritdoc />
    [Obsolete("Use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => _hasPrivateKey;

    /// <inheritdoc />
    public override PrivateKeyStatus PrivateKeyStatus =>
        _hasPrivateKey ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

    /// <inheritdoc />
    public override int KeySize => Algorithm.PublicKeySizeInBytes * 8;

    // ── Static factory methods ───────────────────────────────────

    /// <summary>
    /// Generates a new ML-DSA key pair.
    /// </summary>
    /// <param name="algorithm">The ML-DSA variant to use. Defaults to ML-DSA-65 (recommended).</param>
    /// <returns>A new <see cref="MlDsaSecurityKey"/> containing both public and private keys.</returns>
    public static MlDsaSecurityKey Generate(MLDsaAlgorithm? algorithm = null)
    {
        ThrowIfPlatformUnsupported();
        var mlDsa = MLDsa.GenerateKey(algorithm ?? MLDsaAlgorithm.MLDsa65);
        return new MlDsaSecurityKey(mlDsa, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported public key (verification only).
    /// </summary>
    /// <param name="publicKey">The raw ML-DSA public key bytes.</param>
    /// <param name="algorithm">The ML-DSA variant that produced this key.</param>
    public static MlDsaSecurityKey FromPublicKey(byte[] publicKey, MLDsaAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(publicKey);
        var mlDsa = MLDsa.ImportMLDsaPublicKey(algorithm, publicKey);
        return new MlDsaSecurityKey(mlDsa, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported private key (signing and verification).
    /// </summary>
    /// <param name="privateKey">The raw ML-DSA private key bytes.</param>
    /// <param name="algorithm">The ML-DSA variant that produced this key.</param>
    public static MlDsaSecurityKey FromPrivateKey(byte[] privateKey, MLDsaAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(privateKey);
        var mlDsa = MLDsa.ImportMLDsaPrivateKey(algorithm, privateKey);
        return new MlDsaSecurityKey(mlDsa, ownsKey: true);
    }

    // ── Export methods ───────────────────────────────────────────

    /// <summary>
    /// Exports the public key as a raw byte array.
    /// </summary>
    public byte[] ExportPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return MlDsa.ExportMLDsaPublicKey();
    }

    /// <summary>
    /// Exports the private key as a raw byte array.
    /// </summary>
    /// <exception cref="InvalidOperationException">This key does not contain a private key.</exception>
    public byte[] ExportPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasPrivateKey)
            throw new InvalidOperationException("This key does not contain a private key.");
        return MlDsa.ExportMLDsaPrivateKey();
    }

    // ── IDisposable ──────────────────────────────────────────────

    /// <summary>
    /// Disposes the underlying <see cref="MLDsa"/> if this key owns it.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsKey)
            MlDsa.Dispose();
    }

    // ── Private helpers ──────────────────────────────────────────

    private static void ThrowIfPlatformUnsupported()
    {
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported on this platform. " +
                "Requires Windows 11 / Server 2025 or Linux with OpenSSL 3.5+. " +
                "macOS is not yet supported.");
    }

    private static bool TryDetectPrivateKey(MLDsa mlDsa)
    {
        try
        {
            _ = mlDsa.ExportMLDsaPrivateKey();
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string GenerateKeyId(MLDsa mlDsa)
    {
        var publicKey = mlDsa.ExportMLDsaPublicKey();
        var hash = SHA256.HashData(publicKey);
        return Base64UrlEncoder.Encode(hash);
    }
}
