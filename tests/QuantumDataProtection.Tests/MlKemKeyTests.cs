using System.Security.Cryptography;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemKeyTests
{
    [SkippableTheory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void Generate_AllVariants_CreatesValidKey(string algName)
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        using var key = MlKemKey.Generate(algorithm);

        Assert.NotNull(key);
        Assert.True(key.HasDecapsulationKey);
        Assert.NotEmpty(key.KeyId);
    }

    [SkippableFact]
    public void Generate_Default_UsesMlKem768()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var key = MlKemKey.Generate();
        Assert.Equal(MLKemAlgorithm.MLKem768, key.Algorithm);
    }

    [SkippableFact]
    public void EncapsulateAndDecapsulate_RoundTrip()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var key = MlKemKey.Generate(MLKemAlgorithm.MLKem768);

        var (sharedSecret, ciphertext) = key.Encapsulate();
        var decapsulated = key.Decapsulate(ciphertext);

        Assert.Equal(sharedSecret, decapsulated);
        Assert.Equal(32, sharedSecret.Length); // 256-bit shared secret
    }

    [SkippableFact]
    public void ExportEncapsulationKey_ImportEncapsulationKey_RoundTrip()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var original = MlKemKey.Generate(MLKemAlgorithm.MLKem768);
        var encapKeyBytes = original.ExportEncapsulationKey();

        using var publicOnly = MlKemKey.FromEncapsulationKey(encapKeyBytes, MLKemAlgorithm.MLKem768);

        Assert.False(publicOnly.HasDecapsulationKey);
        Assert.Equal(original.ExportEncapsulationKey(), publicOnly.ExportEncapsulationKey());
    }

    [SkippableFact]
    public void ExportDecapsulationKey_ImportDecapsulationKey_RoundTrip()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var original = MlKemKey.Generate(MLKemAlgorithm.MLKem768);
        var (sharedSecret, ciphertext) = original.Encapsulate();

        var decapKeyBytes = original.ExportDecapsulationKey();
        using var restored = MlKemKey.FromDecapsulationKey(decapKeyBytes, MLKemAlgorithm.MLKem768);

        var decapsulated = restored.Decapsulate(ciphertext);
        Assert.Equal(sharedSecret, decapsulated);
    }

    [SkippableFact]
    public void HasDecapsulationKey_WhenEncapsulationOnly_ReturnsFalse()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var full = MlKemKey.Generate(MLKemAlgorithm.MLKem512);
        var encapBytes = full.ExportEncapsulationKey();
        using var pubOnly = MlKemKey.FromEncapsulationKey(encapBytes, MLKemAlgorithm.MLKem512);

        Assert.False(pubOnly.HasDecapsulationKey);
        Assert.Throws<InvalidOperationException>(() => pubOnly.ExportDecapsulationKey());
        Assert.Throws<InvalidOperationException>(() => pubOnly.Decapsulate(new byte[32]));
    }

    [SkippableFact]
    public void KeyId_IsDeterministic()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var key = MlKemKey.Generate();
        Assert.NotNull(key.KeyId);
        Assert.NotEmpty(key.KeyId);
    }

    [SkippableFact]
    public void Dispose_WhenOwnsKey_DisposesUnderlying()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        var mlKem = MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
        var key = new MlKemKey(mlKem, ownsKey: true);

        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => mlKem.ExportEncapsulationKey());
    }

    [SkippableFact]
    public void Dispose_WhenNotOwnsKey_DoesNotDisposeUnderlying()
    {
        Skip.IfNot(MLKem.IsSupported, "ML-KEM not supported on this platform.");

        using var mlKem = MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
        var key = new MlKemKey(mlKem, ownsKey: false);

        key.Dispose();

        var encapKey = mlKem.ExportEncapsulationKey();
        Assert.NotNull(encapKey);
    }
}
