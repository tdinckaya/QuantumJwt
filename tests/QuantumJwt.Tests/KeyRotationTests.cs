using System.Security.Cryptography;
using Xunit;

namespace QuantumJwt.Tests;

public class KeyRotationTests
{
    [SkippableFact]
    public async Task InitialKey_IsGenerated_OnStart()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var options = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa65,
            RotationInterval = TimeSpan.FromHours(1)
        };

        using var service = new KeyRotationService(options);
        await service.StartAsync(CancellationToken.None);

        Assert.NotNull(service.CurrentSigningKey);
        Assert.NotEmpty(service.CurrentSigningKey.KeyId);
        Assert.Equal(MLDsaAlgorithm.MLDsa65, service.CurrentSigningKey.Algorithm);

        await service.StopAsync(CancellationToken.None);
    }

    [SkippableFact]
    public async Task KeyRotation_GeneratesNewKey_AfterManualRotation()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var options = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa65,
            RotationInterval = TimeSpan.FromHours(24),
            KeyOverlapPeriod = TimeSpan.FromMinutes(5)
        };

        using var service = new KeyRotationService(options);
        await service.StartAsync(CancellationToken.None);

        var firstKeyId = service.CurrentSigningKey.KeyId;

        // Manually trigger rotation
        await service.RotateKeyAsync();

        var secondKeyId = service.CurrentSigningKey.KeyId;

        Assert.NotEqual(firstKeyId, secondKeyId);

        await service.StopAsync(CancellationToken.None);
    }

    [SkippableFact]
    public async Task OldKey_RemainsValid_DuringOverlapPeriod()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var options = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa44,
            RotationInterval = TimeSpan.FromHours(24),
            KeyOverlapPeriod = TimeSpan.FromHours(1)
        };

        using var service = new KeyRotationService(options);
        await service.StartAsync(CancellationToken.None);

        var firstKeyId = service.CurrentSigningKey.KeyId;

        await service.RotateKeyAsync();

        // Both keys should be in validation set
        var allKeys = service.AllValidationKeys;
        Assert.True(allKeys.Count >= 2, $"Expected at least 2 keys during overlap, got {allKeys.Count}");
        Assert.Contains(allKeys, k => k.KeyId == firstKeyId);
        Assert.Contains(allKeys, k => k.KeyId == service.CurrentSigningKey.KeyId);

        await service.StopAsync(CancellationToken.None);
    }

    [SkippableFact]
    public async Task AllValidationKeys_ContainsBothKeys_DuringOverlap()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var options = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa65,
            RotationInterval = TimeSpan.FromHours(24),
            KeyOverlapPeriod = TimeSpan.FromHours(1)
        };

        using var service = new KeyRotationService(options);
        await service.StartAsync(CancellationToken.None);

        // Start with 1 key
        Assert.Single(service.AllValidationKeys);

        // Rotate → now 2 keys
        await service.RotateKeyAsync();
        Assert.Equal(2, service.AllValidationKeys.Count);

        // Rotate again → now 3 keys
        await service.RotateKeyAsync();
        Assert.Equal(3, service.AllValidationKeys.Count);

        await service.StopAsync(CancellationToken.None);
    }

    [SkippableFact]
    public async Task OnKeyRotated_Callback_IsCalled()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        MlDsaSecurityKey? rotatedKey = null;
        var options = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa44,
            RotationInterval = TimeSpan.FromHours(24),
            OnKeyRotated = key =>
            {
                rotatedKey = key;
                return Task.CompletedTask;
            }
        };

        using var service = new KeyRotationService(options);
        await service.StartAsync(CancellationToken.None);

        // OnKeyRotated is called on initial key generation
        Assert.NotNull(rotatedKey);
        Assert.Equal(service.CurrentSigningKey.KeyId, rotatedKey!.KeyId);

        await service.StopAsync(CancellationToken.None);
    }

    [SkippableFact]
    public void CurrentSigningKey_BeforeStart_ThrowsInvalidOperation()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var options = new KeyRotationOptions();
        using var service = new KeyRotationService(options);

        Assert.Throws<InvalidOperationException>(() => service.CurrentSigningKey);
    }
}
