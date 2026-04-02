using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using QuantumJwt;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemXmlEncryptorTests : IDisposable
{
    private readonly string _testDir;

    public MlKemXmlEncryptorTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"qdp-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    private MlKemDataProtectionOptions CreateOptions(MLKemAlgorithm? algorithm = null)
    {
        return new MlKemDataProtectionOptions
        {
            Algorithm = algorithm ?? MLKemAlgorithm.MLKem768,
            KeyStoreDirectory = _testDir,
            KeyStorePassword = "test-password-xyz"
        };
    }

    [SkippableFact]
    public void Encrypt_ProducesValidXmlStructure()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var plaintext = new XElement("root", new XElement("secret", "hello-world"));

        var result = encryptor.Encrypt(plaintext);

        Assert.Equal(typeof(MlKemXmlDecryptor), result.DecryptorType);

        var xml = result.EncryptedElement;
        Assert.Equal("mlKemEncryptedKey", xml.Name.LocalName);
        Assert.NotNull(xml.Element("algorithm"));
        Assert.NotNull(xml.Element("keyId"));
        Assert.NotNull(xml.Element("kemCiphertext"));
        Assert.NotNull(xml.Element("nonce"));
        Assert.NotNull(xml.Element("ciphertext"));
        Assert.NotNull(xml.Element("tag"));
        Assert.Equal("ML-KEM-768", xml.Element("algorithm")!.Value);
    }

    [SkippableFact]
    public void Encrypt_SavesDecapsulationKeyToStore()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var plaintext = new XElement("root", "test");

        var result = encryptor.Encrypt(plaintext);
        var keyId = result.EncryptedElement.Element("keyId")!.Value;

        var store = options.ResolveKeyStore();
        var savedKey = store.LoadPrivateKeyAsync(keyId).GetAwaiter().GetResult();

        Assert.NotNull(savedKey);
        Assert.True(savedKey!.Length > 0);
    }

    [SkippableTheory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void EncryptDecrypt_RoundTrip_AllAlgorithms(string algName)
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        var options = CreateOptions(algorithm);
        var encryptor = new MlKemXmlEncryptor(options);

        var original = new XElement("root",
            new XElement("key", "my-secret-key"),
            new XElement("value", "sensitive-data-12345"));

        var encrypted = encryptor.Encrypt(original);

        // Decrypt
        var services = new ServiceCollection();
        services.AddSingleton(options);
        var sp = services.BuildServiceProvider();

        var decryptor = new MlKemXmlDecryptor(sp);
        var decrypted = decryptor.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    [SkippableFact]
    public void EncryptDecrypt_LargeXml_Works()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);

        // Simulate a realistic Data Protection XML key
        var original = new XElement("key",
            new XAttribute("id", Guid.NewGuid()),
            new XAttribute("version", 1),
            new XElement("creationDate", DateTimeOffset.UtcNow),
            new XElement("activationDate", DateTimeOffset.UtcNow),
            new XElement("expirationDate", DateTimeOffset.UtcNow.AddDays(90)),
            new XElement("descriptor",
                new XElement("secret", Convert.ToBase64String(RandomNumberGenerator.GetBytes(256)))));

        var encrypted = encryptor.Encrypt(original);

        var services = new ServiceCollection();
        services.AddSingleton(options);
        var sp = services.BuildServiceProvider();

        var decryptor = new MlKemXmlDecryptor(sp);
        var decrypted = decryptor.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }
}
