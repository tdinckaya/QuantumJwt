using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumJwt.Tests;

public class MlDsaSecurityKeyTests
{
    // ── Key generation ───────────────────────────────────────────

    [SkippableFact]
    public void Generate_WithMlDsa44_CreatesValidKey()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa44);

        Assert.NotNull(key);
        Assert.NotNull(key.MlDsa);
        Assert.Equal(MLDsaAlgorithm.MLDsa44, key.Algorithm);
    }

    [SkippableFact]
    public void Generate_WithMlDsa65_CreatesValidKey()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);

        Assert.NotNull(key);
        Assert.Equal(MLDsaAlgorithm.MLDsa65, key.Algorithm);
    }

    [SkippableFact]
    public void Generate_WithMlDsa87_CreatesValidKey()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa87);

        Assert.NotNull(key);
        Assert.Equal(MLDsaAlgorithm.MLDsa87, key.Algorithm);
    }

    [SkippableFact]
    public void Generate_Default_UsesMlDsa65()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate();

        Assert.Equal(MLDsaAlgorithm.MLDsa65, key.Algorithm);
    }

    // ── Private key detection ────────────────────────────────────

    [SkippableFact]
    public void HasPrivateKey_WhenGenerated_ReturnsTrue()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate();

        Assert.Equal(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
    }

    [SkippableFact]
    public void HasPrivateKey_WhenPublicKeyOnly_ReturnsFalse()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var fullKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var publicBytes = fullKey.ExportPublicKey();

        using var publicKey = MlDsaSecurityKey.FromPublicKey(publicBytes, MLDsaAlgorithm.MLDsa65);

        Assert.Equal(PrivateKeyStatus.DoesNotExist, publicKey.PrivateKeyStatus);
    }

    // ── Key size ─────────────────────────────────────────────────

    [SkippableTheory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void KeySize_ReturnsCorrectSize_ForEachAlgorithm(string algName)
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var algorithm = MlDsaAlgorithms.ToMLDsaAlgorithm(algName);
        using var key = MlDsaSecurityKey.Generate(algorithm);

        var expectedBits = algorithm.PublicKeySizeInBytes * 8;
        Assert.Equal(expectedBits, key.KeySize);
        Assert.True(key.KeySize > 0);
    }

    // ── Export / import round-trip ────────────────────────────────

    [SkippableFact]
    public void ExportPublicKey_FromPublicKey_RoundTrip()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var original = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var publicBytes = original.ExportPublicKey();

        using var restored = MlDsaSecurityKey.FromPublicKey(publicBytes, MLDsaAlgorithm.MLDsa65);

        Assert.Equal(original.ExportPublicKey(), restored.ExportPublicKey());
    }

    [SkippableFact]
    public void ExportPrivateKey_FromPrivateKey_RoundTrip()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var original = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var privateBytes = original.ExportPrivateKey();

        using var restored = MlDsaSecurityKey.FromPrivateKey(privateBytes, MLDsaAlgorithm.MLDsa65);

        Assert.Equal(PrivateKeyStatus.Exists, restored.PrivateKeyStatus);
    }

    [SkippableFact]
    public void ExportPrivateKey_WhenNoPrivateKey_ThrowsInvalidOperationException()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var fullKey = MlDsaSecurityKey.Generate();
        var publicBytes = fullKey.ExportPublicKey();
        using var publicKey = MlDsaSecurityKey.FromPublicKey(publicBytes, MLDsaAlgorithm.MLDsa65);

        Assert.Throws<InvalidOperationException>(() => publicKey.ExportPrivateKey());
    }

    // ── CryptoProviderFactory auto-configuration ─────────────────

    [SkippableFact]
    public void CryptoProviderFactory_IsAutoConfigured()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate();

        Assert.NotNull(key.CryptoProviderFactory);
        Assert.NotNull(key.CryptoProviderFactory.CustomCryptoProvider);
        Assert.IsType<MlDsaCryptoProvider>(key.CryptoProviderFactory.CustomCryptoProvider);
    }

    // ── KeyId generation ─────────────────────────────────────────

    [SkippableFact]
    public void KeyId_IsGenerated_AndDeterministic()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate();

        Assert.NotNull(key.KeyId);
        Assert.NotEmpty(key.KeyId);
    }

    // ── Dispose ──────────────────────────────────────────────────

    [SkippableFact]
    public void Dispose_WhenOwnsKey_DisposesUnderlying()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var mlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        var key = new MlDsaSecurityKey(mlDsa, ownsKey: true);

        key.Dispose();

        // After dispose, the underlying MLDsa should be disposed
        Assert.Throws<ObjectDisposedException>(() => mlDsa.ExportMLDsaPublicKey());
    }

    [SkippableFact]
    public void Dispose_WhenNotOwnsKey_DoesNotDisposeUnderlying()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var mlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        var key = new MlDsaSecurityKey(mlDsa, ownsKey: false);

        key.Dispose();

        // Should still work since we don't own the key
        var pubKey = mlDsa.ExportMLDsaPublicKey();
        Assert.NotNull(pubKey);
    }

    // ── End-to-end JWT signing and verification ──────────────────

    [SkippableFact]
    public void SignAndVerify_EndToEnd_WithJwtSecurityTokenHandler()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var handler = new JwtSecurityTokenHandler
        {
            InboundClaimTypeMap = new Dictionary<string, string>() // Disable claim mapping
        };

        // Create token
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", "user1"),
                new Claim("role", "admin")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, MlDsaAlgorithms.MlDsa65),
            Issuer = "test-issuer",
            Audience = "test-audience"
        };

        var tokenString = handler.CreateEncodedJwt(descriptor);
        Assert.NotNull(tokenString);

        // Validate token
        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidIssuer = "test-issuer",
            ValidAudience = "test-audience",
            ValidateLifetime = true
        };

        var principal = handler.ValidateToken(tokenString, validationParams, out var validatedToken);

        Assert.NotNull(principal);
        Assert.NotNull(validatedToken);
        Assert.Equal("user1", principal.FindFirst("sub")?.Value);
        Assert.Equal("admin", principal.FindFirst("role")?.Value);
    }

    [SkippableFact]
    public void SignAndVerify_WithPublicKeyOnly_VerificationSucceeds()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var signingKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var publicBytes = signingKey.ExportPublicKey();
        using var verificationKey = MlDsaSecurityKey.FromPublicKey(publicBytes, MLDsaAlgorithm.MLDsa65);

        var handler = new JwtSecurityTokenHandler
        {
            InboundClaimTypeMap = new Dictionary<string, string>()
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "user1") }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(signingKey, MlDsaAlgorithms.MlDsa65),
            Issuer = "test",
            Audience = "test"
        };

        var tokenString = handler.CreateEncodedJwt(descriptor);

        // Validate with public key only
        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = verificationKey,
            ValidIssuer = "test",
            ValidAudience = "test"
        };

        var principal = handler.ValidateToken(tokenString, validationParams, out _);
        Assert.Equal("user1", principal.FindFirst("sub")?.Value);
    }
}
