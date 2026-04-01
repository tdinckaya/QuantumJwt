using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumJwt.Tests;

public class FileKeyStoreTests : IDisposable
{
    private readonly string _testDir;
    private readonly FileKeyStore _store;

    public FileKeyStoreTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"quantumjwt-test-{Guid.NewGuid():N}");
        _store = new FileKeyStore(_testDir, "test-password-123!");
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    [Fact]
    public async Task SaveAndLoad_RoundTrip()
    {
        var keyId = "test-key-1";
        var testData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        await _store.SavePrivateKeyAsync(keyId, testData);
        var loaded = await _store.LoadPrivateKeyAsync(keyId);

        Assert.NotNull(loaded);
        Assert.Equal(testData, loaded);
    }

    [SkippableFact]
    public async Task EncryptAndDecrypt_MlDsaKey_RoundTrip()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var originalKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var originalPublicKey = originalKey.ExportPublicKey();

        // Encrypt and save
        var encrypted = _store.EncryptKey(originalKey);
        await _store.SavePrivateKeyAsync(originalKey.KeyId, encrypted);

        // Load and decrypt
        var loadedEncrypted = await _store.LoadPrivateKeyAsync(originalKey.KeyId);
        Assert.NotNull(loadedEncrypted);

        using var restoredKey = _store.DecryptKey(loadedEncrypted!, MLDsaAlgorithm.MLDsa65);

        Assert.Equal(PrivateKeyStatus.Exists, restoredKey.PrivateKeyStatus);
    }

    [Fact]
    public async Task ListKeyIds_ReturnsAllSaved()
    {
        await _store.SavePrivateKeyAsync("key-a", new byte[] { 1 });
        await _store.SavePrivateKeyAsync("key-b", new byte[] { 2 });
        await _store.SavePrivateKeyAsync("key-c", new byte[] { 3 });

        var ids = await _store.ListKeyIdsAsync();

        Assert.Equal(3, ids.Count);
        Assert.Contains("key-a", ids);
        Assert.Contains("key-b", ids);
        Assert.Contains("key-c", ids);
    }

    [Fact]
    public async Task DeleteKey_RemovesFile()
    {
        await _store.SavePrivateKeyAsync("delete-me", new byte[] { 1 });

        var before = await _store.LoadPrivateKeyAsync("delete-me");
        Assert.NotNull(before);

        await _store.DeleteKeyAsync("delete-me");

        var after = await _store.LoadPrivateKeyAsync("delete-me");
        Assert.Null(after);
    }

    [Fact]
    public async Task LoadNonExistent_ReturnsNull()
    {
        var result = await _store.LoadPrivateKeyAsync("does-not-exist");
        Assert.Null(result);
    }

    [Fact]
    public void Constructor_CreatesDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"quantumjwt-mkdir-{Guid.NewGuid():N}");
        try
        {
            _ = new FileKeyStore(dir, "password");
            Assert.True(Directory.Exists(dir));
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task PathTraversal_IsSanitized()
    {
        // Key IDs with path traversal characters should be sanitized
        await _store.SavePrivateKeyAsync("../../../etc/passwd", new byte[] { 1 });

        // Should NOT create a file outside the test directory
        var ids = await _store.ListKeyIdsAsync();
        Assert.Single(ids);
        Assert.DoesNotContain("/", ids[0]);
        Assert.DoesNotContain("..", ids[0]);
    }
}
