using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using QuantumJwt;

namespace QuantumDataProtection;

/// <summary>
/// <see cref="IXmlDecryptor"/> that decrypts Data Protection XML keys
/// encrypted by <see cref="MlKemXmlEncryptor"/>.
/// </summary>
public sealed class MlKemXmlDecryptor : IXmlDecryptor
{
    private readonly IKeyStore _keyStore;

    /// <summary>
    /// Initializes a new <see cref="MlKemXmlDecryptor"/>.
    /// </summary>
    public MlKemXmlDecryptor(IServiceProvider services)
    {
        var options = services.GetRequiredService<MlKemDataProtectionOptions>();
        _keyStore = options.ResolveKeyStore();
    }

    /// <summary>
    /// Decrypts an XML element that was encrypted by <see cref="MlKemXmlEncryptor"/>.
    /// </summary>
    public XElement Decrypt(XElement encryptedElement)
    {
        // Parse XML
        var algorithmStr = encryptedElement.Element("algorithm")?.Value
            ?? throw new CryptographicException("Missing 'algorithm' element.");
        var keyId = encryptedElement.Element("keyId")?.Value
            ?? throw new CryptographicException("Missing 'keyId' element.");
        var kemCiphertext = Convert.FromBase64String(
            encryptedElement.Element("kemCiphertext")?.Value
            ?? throw new CryptographicException("Missing 'kemCiphertext' element."));
        var nonce = Convert.FromBase64String(
            encryptedElement.Element("nonce")?.Value
            ?? throw new CryptographicException("Missing 'nonce' element."));
        var ciphertext = Convert.FromBase64String(
            encryptedElement.Element("ciphertext")?.Value
            ?? throw new CryptographicException("Missing 'ciphertext' element."));
        var tag = Convert.FromBase64String(
            encryptedElement.Element("tag")?.Value
            ?? throw new CryptographicException("Missing 'tag' element."));

        // Load decapsulation key from store
        var encryptedDecapKey = _keyStore.LoadPrivateKeyAsync(keyId)
            .GetAwaiter().GetResult()
            ?? throw new CryptographicException($"Decapsulation key '{keyId}' not found in key store.");

        // Import the decapsulation key
        using var mlKem = MLKem.ImportEncryptedPkcs8PrivateKey("quantum-dp-key", encryptedDecapKey);

        // Decapsulate → shared secret
        var sharedSecret = mlKem.Decapsulate(kemCiphertext);

        try
        {
            // AES-256-GCM decrypt
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(sharedSecret, tagSizeInBytes: 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            var xml = System.Text.Encoding.UTF8.GetString(plaintext);
            return XElement.Parse(xml);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
