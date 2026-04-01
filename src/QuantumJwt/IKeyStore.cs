namespace QuantumJwt;

/// <summary>
/// Abstraction for securely storing and retrieving ML-DSA private keys.
/// <para>
/// Implement this interface to integrate with your key management system
/// (Azure Key Vault, AWS KMS, HashiCorp Vault, etc.).
/// </para>
/// <para>
/// The built-in <see cref="FileKeyStore"/> provides encrypted file-based
/// storage for development and simple deployments.
/// </para>
/// </summary>
public interface IKeyStore
{
    /// <summary>
    /// Loads an encrypted private key by its identifier.
    /// </summary>
    /// <param name="keyId">The unique key identifier (matches <see cref="Microsoft.IdentityModel.Tokens.SecurityKey.KeyId"/>).</param>
    /// <returns>The encrypted PKCS#8 private key bytes, or <c>null</c> if not found.</returns>
    Task<byte[]?> LoadPrivateKeyAsync(string keyId);

    /// <summary>
    /// Saves an encrypted private key.
    /// </summary>
    /// <param name="keyId">The unique key identifier.</param>
    /// <param name="encryptedKey">The encrypted PKCS#8 private key bytes.</param>
    Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey);

    /// <summary>
    /// Deletes a private key from the store.
    /// </summary>
    /// <param name="keyId">The unique key identifier.</param>
    Task DeleteKeyAsync(string keyId);

    /// <summary>
    /// Lists all stored key identifiers.
    /// </summary>
    Task<IReadOnlyList<string>> ListKeyIdsAsync();
}
