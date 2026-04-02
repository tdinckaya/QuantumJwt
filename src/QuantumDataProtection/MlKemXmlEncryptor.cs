using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using QuantumJwt;

namespace QuantumDataProtection;

/// <summary>
/// <see cref="IXmlEncryptor"/> that protects Data Protection XML keys using
/// ML-KEM (FIPS 203) key encapsulation + AES-256-GCM symmetric encryption.
/// <para>
/// For each key, a fresh ML-KEM keypair is generated. The shared secret from
/// encapsulation is used as the AES-256-GCM key. The decapsulation key is
/// stored in the configured <see cref="IKeyStore"/>.
/// </para>
/// </summary>
public sealed class MlKemXmlEncryptor : IXmlEncryptor
{
    private readonly MlKemDataProtectionOptions _options;
    private readonly IKeyStore _keyStore;

    /// <summary>
    /// Initializes a new <see cref="MlKemXmlEncryptor"/>.
    /// </summary>
    public MlKemXmlEncryptor(MlKemDataProtectionOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _keyStore = options.ResolveKeyStore();
    }

    /// <summary>
    /// Encrypts the given XML element using ML-KEM + AES-256-GCM.
    /// </summary>
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var plaintext = System.Text.Encoding.UTF8.GetBytes(plaintextElement.ToString());

        // Generate a fresh ML-KEM keypair for this XML key
        using var kemKey = MlKemKey.Generate(_options.Algorithm);

        // Encapsulate → shared secret + ciphertext
        var (sharedSecret, kemCiphertext) = kemKey.Encapsulate();

        try
        {
            // AES-256-GCM encrypt the XML
            var nonce = new byte[12]; // 96-bit nonce
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16]; // 128-bit tag

            using var aes = new AesGcm(sharedSecret, tagSizeInBytes: 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            // Save decapsulation key to store
            var encryptedDecapKey = kemKey.MlKem.ExportEncryptedPkcs8PrivateKey(
                "quantum-dp-key",
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));

            _keyStore.SavePrivateKeyAsync(kemKey.KeyId, encryptedDecapKey)
                .GetAwaiter().GetResult();

            // Build output XML
            var encryptedElement = new XElement("mlKemEncryptedKey",
                new XElement("algorithm", MlKemAlgorithms.ToAlgorithmString(kemKey.Algorithm)),
                new XElement("keyId", kemKey.KeyId),
                new XElement("kemCiphertext", Convert.ToBase64String(kemCiphertext)),
                new XElement("nonce", Convert.ToBase64String(nonce)),
                new XElement("ciphertext", Convert.ToBase64String(ciphertext)),
                new XElement("tag", Convert.ToBase64String(tag)));

            return new EncryptedXmlInfo(encryptedElement, typeof(MlKemXmlDecryptor));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
