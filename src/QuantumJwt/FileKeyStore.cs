using System.Security.Cryptography;

namespace QuantumJwt;

/// <summary>
/// File-based <see cref="IKeyStore"/> that stores ML-DSA private keys as
/// encrypted PKCS#8 files on disk.
/// <para>
/// Each key is saved as <c>{keyId}.p8</c> in the configured directory,
/// encrypted with AES-256-CBC + SHA-256 PBKDF2 (100,000 iterations).
/// </para>
/// <para>
/// <b>For production use:</b> Consider implementing <see cref="IKeyStore"/>
/// with Azure Key Vault, AWS KMS, or HashiCorp Vault instead.
/// </para>
/// </summary>
public sealed class FileKeyStore : IKeyStore
{
    private readonly string _directory;
    private readonly byte[] _password;
    private static readonly PbeParameters PbeParams = new(
        PbeEncryptionAlgorithm.Aes256Cbc,
        HashAlgorithmName.SHA256,
        iterationCount: 100_000);

    /// <summary>
    /// Initializes a new <see cref="FileKeyStore"/>.
    /// </summary>
    /// <param name="directory">
    /// Directory to store key files. Created automatically if it doesn't exist.
    /// </param>
    /// <param name="password">
    /// Password used to encrypt/decrypt private keys.
    /// <b>Do not hard-code this.</b> Load from a secure source (env var, secret manager).
    /// </param>
    public FileKeyStore(string directory, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        _directory = directory;
        _password = System.Text.Encoding.UTF8.GetBytes(password);

        Directory.CreateDirectory(_directory);
    }

    /// <inheritdoc />
    public Task<byte[]?> LoadPrivateKeyAsync(string keyId)
    {
        var path = GetKeyPath(keyId);
        if (!File.Exists(path))
            return Task.FromResult<byte[]?>(null);

        var encrypted = File.ReadAllBytes(path);
        return Task.FromResult<byte[]?>(encrypted);
    }

    /// <inheritdoc />
    public Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey)
    {
        ArgumentNullException.ThrowIfNull(encryptedKey);

        var path = GetKeyPath(keyId);
        File.WriteAllBytes(path, encryptedKey);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeleteKeyAsync(string keyId)
    {
        var path = GetKeyPath(keyId);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ListKeyIdsAsync()
    {
        if (!Directory.Exists(_directory))
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        var keyIds = Directory.GetFiles(_directory, "*.p8")
            .Select(f => Path.GetFileNameWithoutExtension(f))
            .ToList();

        return Task.FromResult<IReadOnlyList<string>>(keyIds);
    }

    /// <summary>
    /// Encrypts an ML-DSA private key for storage.
    /// </summary>
    /// <param name="key">The key to encrypt.</param>
    /// <returns>Encrypted PKCS#8 bytes ready for <see cref="SavePrivateKeyAsync"/>.</returns>
    public byte[] EncryptKey(MlDsaSecurityKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.MlDsa.ExportEncryptedPkcs8PrivateKey(_password, PbeParams);
    }

    /// <summary>
    /// Decrypts a stored private key.
    /// </summary>
    /// <param name="encryptedKey">The encrypted PKCS#8 bytes.</param>
    /// <param name="algorithm">The ML-DSA algorithm variant.</param>
    /// <returns>A new <see cref="MlDsaSecurityKey"/> with the decrypted private key.</returns>
    public MlDsaSecurityKey DecryptKey(byte[] encryptedKey, MLDsaAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(encryptedKey);
        var mlDsa = MLDsa.ImportEncryptedPkcs8PrivateKey(_password, encryptedKey);
        return new MlDsaSecurityKey(mlDsa, ownsKey: true);
    }

    private string GetKeyPath(string keyId)
    {
        // Sanitize keyId to prevent path traversal
        var safeId = string.Concat(keyId.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_'));
        if (string.IsNullOrEmpty(safeId))
            throw new ArgumentException("Key ID contains no valid characters.", nameof(keyId));
        return Path.Combine(_directory, $"{safeId}.p8");
    }
}
