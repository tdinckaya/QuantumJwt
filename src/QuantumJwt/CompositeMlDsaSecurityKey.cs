using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// A <see cref="SecurityKey"/> that wraps a .NET 10 <see cref="CompositeMLDsa"/> instance
/// for hybrid post-quantum JWT signing. Produces both a classical (RSA/ECDSA/Ed25519)
/// and an ML-DSA signature in the same token.
/// <para>
/// This is the strongest option for the transition period — even if quantum computers
/// break ML-DSA, the classical signature still protects the token (and vice-versa).
/// </para>
/// </summary>
public sealed class CompositeMlDsaSecurityKey : AsymmetricSecurityKey, IDisposable
{
    private readonly bool _ownsKey;
    private readonly bool _hasPrivateKey;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance wrapping an existing <see cref="CompositeMLDsa"/> key.
    /// </summary>
    /// <param name="compositeKey">The composite ML-DSA key instance.</param>
    /// <param name="ownsKey">
    /// If <c>true</c> (default), the underlying key will be disposed when this
    /// instance is disposed.
    /// </param>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when the current platform does not support Composite ML-DSA.
    /// </exception>
    public CompositeMlDsaSecurityKey(CompositeMLDsa compositeKey, bool ownsKey = true)
    {
        ThrowIfPlatformUnsupported();

        CompositeKey = compositeKey ?? throw new ArgumentNullException(nameof(compositeKey));
        Algorithm = compositeKey.Algorithm;
        _ownsKey = ownsKey;
        _hasPrivateKey = TryDetectPrivateKey(compositeKey);

        CryptoProviderFactory = new CryptoProviderFactory
        {
            CustomCryptoProvider = new MlDsaCryptoProvider()
        };

        KeyId = GenerateKeyId(compositeKey);
    }

    /// <summary>The underlying <see cref="CompositeMLDsa"/> instance.</summary>
    public CompositeMLDsa CompositeKey { get; }

    /// <summary>The composite ML-DSA algorithm variant.</summary>
    public CompositeMLDsaAlgorithm Algorithm { get; }

    /// <inheritdoc />
    [Obsolete("Use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => _hasPrivateKey;

    /// <inheritdoc />
    public override PrivateKeyStatus PrivateKeyStatus =>
        _hasPrivateKey ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

    /// <inheritdoc />
    public override int KeySize => Algorithm.MaxSignatureSizeInBytes * 8;

    // ── Static factory methods ───────────────────────────────────

    /// <summary>
    /// Generates a new composite ML-DSA key pair.
    /// </summary>
    /// <param name="algorithm">
    /// The composite algorithm to use.
    /// Defaults to <see cref="CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss"/>.
    /// </param>
    public static CompositeMlDsaSecurityKey Generate(CompositeMLDsaAlgorithm? algorithm = null)
    {
        ThrowIfPlatformUnsupported();
        var key = CompositeMLDsa.GenerateKey(algorithm ?? CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);
        return new CompositeMlDsaSecurityKey(key, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported composite public key (verification only).
    /// </summary>
    public static CompositeMlDsaSecurityKey FromPublicKey(byte[] publicKey, CompositeMLDsaAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(publicKey);
        var key = CompositeMLDsa.ImportCompositeMLDsaPublicKey(algorithm, publicKey);
        return new CompositeMlDsaSecurityKey(key, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported composite private key (signing and verification).
    /// </summary>
    public static CompositeMlDsaSecurityKey FromPrivateKey(byte[] privateKey, CompositeMLDsaAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(privateKey);
        var key = CompositeMLDsa.ImportCompositeMLDsaPrivateKey(algorithm, privateKey);
        return new CompositeMlDsaSecurityKey(key, ownsKey: true);
    }

    // ── Export methods ───────────────────────────────────────────

    /// <summary>Exports the composite public key as a raw byte array.</summary>
    public byte[] ExportPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return CompositeKey.ExportCompositeMLDsaPublicKey();
    }

    /// <summary>Exports the composite private key as a raw byte array.</summary>
    /// <exception cref="InvalidOperationException">This key does not contain a private key.</exception>
    public byte[] ExportPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasPrivateKey)
            throw new InvalidOperationException("This key does not contain a private key.");
        return CompositeKey.ExportCompositeMLDsaPrivateKey();
    }

    // ── IDisposable ──────────────────────────────────────────────

    /// <summary>
    /// Disposes the underlying <see cref="CompositeMLDsa"/> if this key owns it.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsKey)
            CompositeKey.Dispose();
    }

    // ── Private helpers ──────────────────────────────────────────

    private static void ThrowIfPlatformUnsupported()
    {
        if (!CompositeMLDsa.IsSupported)
            throw new PlatformNotSupportedException(
                "Composite ML-DSA is not supported on this platform. " +
                "Requires Windows 11 / Server 2025 or Linux with OpenSSL 3.5+. " +
                "macOS is not yet supported.");
    }

    private static bool TryDetectPrivateKey(CompositeMLDsa key)
    {
        try
        {
            _ = key.ExportCompositeMLDsaPrivateKey();
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string GenerateKeyId(CompositeMLDsa key)
    {
        var publicKey = key.ExportCompositeMLDsaPublicKey();
        var hash = SHA256.HashData(publicKey);
        return Base64UrlEncoder.Encode(hash);
    }
}
