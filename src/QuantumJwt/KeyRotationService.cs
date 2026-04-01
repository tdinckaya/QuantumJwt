using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// Configuration for automatic ML-DSA key rotation.
/// </summary>
public sealed class KeyRotationOptions
{
    /// <summary>
    /// How often to rotate the signing key. Defaults to 90 days.
    /// </summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// How long to keep the old key valid for verification after rotation.
    /// During this period, both old and new keys can verify tokens.
    /// Defaults to 7 days.
    /// </summary>
    public TimeSpan KeyOverlapPeriod { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// The ML-DSA algorithm variant for generated keys. Defaults to ML-DSA-65.
    /// </summary>
    public MLDsaAlgorithm Algorithm { get; set; } = MLDsaAlgorithm.MLDsa65;

    /// <summary>
    /// Optional key store for persisting keys across restarts.
    /// If null, keys are in-memory only (suitable for development).
    /// </summary>
    public IKeyStore? KeyStore { get; set; }

    /// <summary>
    /// Called when a new key is generated. Use this to notify external systems
    /// (update Key Vault, refresh JWKS cache, etc.).
    /// </summary>
    public Func<MlDsaSecurityKey, Task>? OnKeyRotated { get; set; }

    /// <summary>
    /// Called when an old key is retired (overlap period expired).
    /// Use this to clean up external resources.
    /// </summary>
    public Func<MlDsaSecurityKey, Task>? OnKeyRetired { get; set; }
}

/// <summary>
/// Background service that automatically rotates ML-DSA signing keys.
/// <para>
/// Generates a new key every <see cref="KeyRotationOptions.RotationInterval"/>,
/// keeps the old key valid for <see cref="KeyRotationOptions.KeyOverlapPeriod"/>,
/// then retires it.
/// </para>
/// <para>
/// Register via <c>AddKeyRotation()</c> extension method.
/// Inject <see cref="KeyRotationService"/> to access <see cref="CurrentSigningKey"/>
/// and <see cref="AllValidationKeys"/>.
/// </para>
/// </summary>
public sealed class KeyRotationService : IHostedService, IDisposable
{
    private readonly KeyRotationOptions _options;
    private readonly ILogger<KeyRotationService>? _logger;
    private readonly ConcurrentDictionary<string, KeyEntry> _keys = new();
    private readonly object _rotationLock = new();
    private Timer? _rotationTimer;
    private Timer? _cleanupTimer;
    private string? _currentKeyId;

    /// <summary>
    /// Initializes a new <see cref="KeyRotationService"/>.
    /// </summary>
    public KeyRotationService(KeyRotationOptions options, ILogger<KeyRotationService>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    /// <summary>
    /// The current signing key. Use this for creating new tokens.
    /// </summary>
    /// <exception cref="InvalidOperationException">Service has not started yet.</exception>
    public MlDsaSecurityKey CurrentSigningKey
    {
        get
        {
            if (_currentKeyId is null || !_keys.TryGetValue(_currentKeyId, out var entry))
                throw new InvalidOperationException(
                    "Key rotation service has not started. Ensure it is registered as a hosted service.");
            return entry.Key;
        }
    }

    /// <summary>
    /// All keys valid for token verification (current + overlap period keys).
    /// Use this for <see cref="TokenValidationParameters.IssuerSigningKeys"/>.
    /// </summary>
    public IReadOnlyList<MlDsaSecurityKey> AllValidationKeys =>
        _keys.Values
            .Where(e => !e.IsRetired)
            .Select(e => e.Key)
            .ToList();

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Try to load existing keys from store
        if (_options.KeyStore is not null)
        {
            await LoadKeysFromStoreAsync();
        }

        // Generate initial key if none loaded
        if (_currentKeyId is null)
        {
            await RotateKeyAsync();
        }

        // Start rotation timer
        _rotationTimer = new Timer(
            _ => _ = RotateKeyAsync(),
            null,
            _options.RotationInterval,
            _options.RotationInterval);

        // Start cleanup timer (check every hour for expired overlap keys)
        _cleanupTimer = new Timer(
            _ => _ = CleanupExpiredKeysAsync(),
            null,
            TimeSpan.FromHours(1),
            TimeSpan.FromHours(1));
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _rotationTimer?.Change(Timeout.Infinite, 0);
        _cleanupTimer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Manually triggers a key rotation. Useful for testing or emergency rotation.
    /// </summary>
    public async Task RotateKeyAsync()
    {
        MlDsaSecurityKey newKey;
        MlDsaSecurityKey? oldKey = null;

        lock (_rotationLock)
        {
            // Mark the current key as "rotating out"
            if (_currentKeyId is not null && _keys.TryGetValue(_currentKeyId, out var currentEntry))
            {
                currentEntry.RotatedAt = DateTimeOffset.UtcNow;
                oldKey = currentEntry.Key;
            }

            // Generate new key
            newKey = MlDsaSecurityKey.Generate(_options.Algorithm);

            var entry = new KeyEntry
            {
                Key = newKey,
                CreatedAt = DateTimeOffset.UtcNow
            };

            _keys[newKey.KeyId] = entry;
            _currentKeyId = newKey.KeyId;
        }

        _logger?.LogInformation(
            "ML-DSA key rotated. New KeyId: {KeyId}, Algorithm: {Algorithm}",
            newKey.KeyId, _options.Algorithm.Name);

        // Persist new key
        if (_options.KeyStore is not null)
        {
            try
            {
                var encrypted = newKey.MlDsa.ExportEncryptedPkcs8PrivateKey(
                    System.Text.Encoding.UTF8.GetBytes("rotation-key"),
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
                await _options.KeyStore.SavePrivateKeyAsync(newKey.KeyId, encrypted);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to persist rotated key {KeyId}", newKey.KeyId);
            }
        }

        // Notify callback
        if (_options.OnKeyRotated is not null)
        {
            try
            {
                await _options.OnKeyRotated(newKey);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "OnKeyRotated callback failed for key {KeyId}", newKey.KeyId);
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _rotationTimer?.Dispose();
        _cleanupTimer?.Dispose();

        foreach (var entry in _keys.Values)
        {
            entry.Key.Dispose();
        }

        _keys.Clear();
    }

    // ── Private ──────────────────────────────────────────────────

    private async Task CleanupExpiredKeysAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var expiredKeys = _keys.Values
            .Where(e => e.RotatedAt.HasValue &&
                        now - e.RotatedAt.Value > _options.KeyOverlapPeriod &&
                        e.Key.KeyId != _currentKeyId)
            .ToList();

        foreach (var expired in expiredKeys)
        {
            expired.IsRetired = true;

            if (_keys.TryRemove(expired.Key.KeyId, out _))
            {
                _logger?.LogInformation("Key retired: {KeyId}", expired.Key.KeyId);

                // Delete from store
                if (_options.KeyStore is not null)
                {
                    try
                    {
                        await _options.KeyStore.DeleteKeyAsync(expired.Key.KeyId);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError(ex, "Failed to delete retired key {KeyId} from store",
                            expired.Key.KeyId);
                    }
                }

                // Notify callback
                if (_options.OnKeyRetired is not null)
                {
                    try
                    {
                        await _options.OnKeyRetired(expired.Key);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError(ex, "OnKeyRetired callback failed for key {KeyId}",
                            expired.Key.KeyId);
                    }
                }

                expired.Key.Dispose();
            }
        }
    }

    private async Task LoadKeysFromStoreAsync()
    {
        if (_options.KeyStore is null) return;

        try
        {
            var keyIds = await _options.KeyStore.ListKeyIdsAsync();
            foreach (var keyId in keyIds)
            {
                var encrypted = await _options.KeyStore.LoadPrivateKeyAsync(keyId);
                if (encrypted is null) continue;

                var mlDsa = MLDsa.ImportEncryptedPkcs8PrivateKey(
                    System.Text.Encoding.UTF8.GetBytes("rotation-key"),
                    encrypted);

                var key = new MlDsaSecurityKey(mlDsa, ownsKey: true);
                var entry = new KeyEntry
                {
                    Key = key,
                    CreatedAt = DateTimeOffset.UtcNow
                };

                _keys[key.KeyId] = entry;
                _currentKeyId = key.KeyId; // Last loaded becomes current
            }

            if (_currentKeyId is not null)
            {
                _logger?.LogInformation("Loaded {Count} keys from store. Current: {KeyId}",
                    keyIds.Count, _currentKeyId);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to load keys from store. Will generate new key.");
        }
    }

    private sealed class KeyEntry
    {
        public required MlDsaSecurityKey Key { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        public DateTimeOffset? RotatedAt { get; set; }
        public bool IsRetired { get; set; }
    }
}
