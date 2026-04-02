using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace QuantumDataProtection;

/// <summary>
/// Wraps a .NET 10 <see cref="MLKem"/> instance for key encapsulation operations.
/// </summary>
public sealed class MlKemKey : IDisposable
{
    private readonly bool _ownsKey;
    private readonly bool _hasDecapsulationKey;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance wrapping an existing <see cref="MLKem"/> key.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when the current platform does not support ML-KEM.
    /// </exception>
    public MlKemKey(MLKem mlKem, bool ownsKey = true)
    {
        ThrowIfPlatformUnsupported();

        MlKem = mlKem ?? throw new ArgumentNullException(nameof(mlKem));
        Algorithm = mlKem.Algorithm;
        _ownsKey = ownsKey;
        _hasDecapsulationKey = TryDetectDecapsulationKey(mlKem);

        KeyId = GenerateKeyId(mlKem);
    }

    /// <summary>The underlying <see cref="MLKem"/> instance.</summary>
    public MLKem MlKem { get; }

    /// <summary>The ML-KEM algorithm variant.</summary>
    public MLKemAlgorithm Algorithm { get; }

    /// <summary>Unique key identifier derived from encapsulation key hash.</summary>
    public string KeyId { get; }

    /// <summary>Whether this key can perform decapsulation (has private key).</summary>
    public bool HasDecapsulationKey => _hasDecapsulationKey;

    // ── Static factory methods ───────────────────────────────────

    /// <summary>
    /// Generates a new ML-KEM key pair (encapsulation + decapsulation).
    /// </summary>
    public static MlKemKey Generate(MLKemAlgorithm? algorithm = null)
    {
        ThrowIfPlatformUnsupported();
        var mlKem = MLKem.GenerateKey(algorithm ?? MLKemAlgorithm.MLKem768);
        return new MlKemKey(mlKem, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported encapsulation key (encrypt/encapsulate only).
    /// </summary>
    public static MlKemKey FromEncapsulationKey(byte[] encapsulationKey, MLKemAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(encapsulationKey);
        var mlKem = MLKem.ImportEncapsulationKey(algorithm, encapsulationKey);
        return new MlKemKey(mlKem, ownsKey: true);
    }

    /// <summary>
    /// Creates a key from an exported decapsulation key (decrypt/decapsulate).
    /// </summary>
    public static MlKemKey FromDecapsulationKey(byte[] decapsulationKey, MLKemAlgorithm algorithm)
    {
        ThrowIfPlatformUnsupported();
        ArgumentNullException.ThrowIfNull(decapsulationKey);
        var mlKem = MLKem.ImportDecapsulationKey(algorithm, decapsulationKey);
        return new MlKemKey(mlKem, ownsKey: true);
    }

    // ── KEM operations ───────────────────────────────────────────

    /// <summary>
    /// Encapsulates a shared secret. Returns the shared secret and ciphertext.
    /// </summary>
    /// <returns>A tuple of (sharedSecret, ciphertext).</returns>
    public (byte[] SharedSecret, byte[] Ciphertext) Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        MlKem.Encapsulate(out var ciphertext, out var sharedSecret);
        return (sharedSecret, ciphertext);
    }

    /// <summary>
    /// Decapsulates a shared secret from ciphertext.
    /// </summary>
    /// <exception cref="InvalidOperationException">This key does not have a decapsulation key.</exception>
    public byte[] Decapsulate(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasDecapsulationKey)
            throw new InvalidOperationException("This key does not contain a decapsulation key.");
        return MlKem.Decapsulate(ciphertext);
    }

    // ── Export methods ───────────────────────────────────────────

    /// <summary>Exports the encapsulation (public) key.</summary>
    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return MlKem.ExportEncapsulationKey();
    }

    /// <summary>Exports the decapsulation (private) key.</summary>
    /// <exception cref="InvalidOperationException">No decapsulation key available.</exception>
    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasDecapsulationKey)
            throw new InvalidOperationException("This key does not contain a decapsulation key.");
        return MlKem.ExportDecapsulationKey();
    }

    // ── IDisposable ──────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsKey)
            MlKem.Dispose();
    }

    // ── Private helpers ──────────────────────────────────────────

    private static void ThrowIfPlatformUnsupported()
    {
        if (!MLKem.IsSupported)
            throw new PlatformNotSupportedException(
                "ML-KEM is not supported on this platform. " +
                "Requires Windows 11 / Server 2025 or Linux with OpenSSL 3.5+. " +
                "macOS is not yet supported.");
    }

    private static bool TryDetectDecapsulationKey(MLKem mlKem)
    {
        try
        {
            _ = mlKem.ExportDecapsulationKey();
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string GenerateKeyId(MLKem mlKem)
    {
        var encapsulationKey = mlKem.ExportEncapsulationKey();
        var hash = SHA256.HashData(encapsulationKey);
        return Base64UrlEncoder.Encode(hash);
    }
}
