using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumJwt.Tests;

public class CompositeMlDsaSecurityKeyTests
{
    [SkippableFact]
    public void Generate_WithDefaultAlgorithm_CreatesValidKey()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var key = CompositeMlDsaSecurityKey.Generate();

        Assert.NotNull(key);
        Assert.NotNull(key.CompositeKey);
        Assert.Equal(CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss, key.Algorithm);
        Assert.Equal(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
    }

    [SkippableFact]
    public void Generate_WithMLDsa65WithECDsaP384_CreatesValidKey()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var key = CompositeMlDsaSecurityKey.Generate(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384);

        Assert.NotNull(key);
        Assert.Equal(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384, key.Algorithm);
    }

    [SkippableFact]
    public void ExportPublicKey_ImportPublicKey_RoundTrip()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var original = CompositeMlDsaSecurityKey.Generate(CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);
        var publicBytes = original.ExportPublicKey();

        using var restored = CompositeMlDsaSecurityKey.FromPublicKey(
            publicBytes, CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);

        Assert.Equal(original.ExportPublicKey(), restored.ExportPublicKey());
        Assert.Equal(PrivateKeyStatus.DoesNotExist, restored.PrivateKeyStatus);
    }

    [SkippableFact]
    public void HasPrivateKey_WhenPublicOnly_ReturnsFalse()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var full = CompositeMlDsaSecurityKey.Generate();
        var pubBytes = full.ExportPublicKey();
        using var pubOnly = CompositeMlDsaSecurityKey.FromPublicKey(
            pubBytes, CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);

        Assert.Equal(PrivateKeyStatus.DoesNotExist, pubOnly.PrivateKeyStatus);
        Assert.Throws<InvalidOperationException>(() => pubOnly.ExportPrivateKey());
    }

    [SkippableFact]
    public void CryptoProviderFactory_IsAutoConfigured()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var key = CompositeMlDsaSecurityKey.Generate();

        Assert.NotNull(key.CryptoProviderFactory);
        Assert.IsType<MlDsaCryptoProvider>(key.CryptoProviderFactory.CustomCryptoProvider);
    }

    [SkippableFact]
    public void SignAndVerify_EndToEnd_Composite()
    {
        Skip.IfNot(CompositeMLDsa.IsSupported, "Composite ML-DSA not supported on this platform.");

        using var key = CompositeMlDsaSecurityKey.Generate(CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);
        var handler = new JwtSecurityTokenHandler();
        var jwtAlg = MlDsaAlgorithms.ToJwtAlgorithm(key.Algorithm);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", "quantum-user"),
                new Claim("tier", "enterprise")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, jwtAlg),
            Issuer = "composite-test",
            Audience = "composite-test"
        };

        var tokenString = handler.CreateEncodedJwt(descriptor);
        Assert.NotNull(tokenString);

        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidIssuer = "composite-test",
            ValidAudience = "composite-test",
            ValidateLifetime = true
        };

        var principal = handler.ValidateToken(tokenString, validationParams, out _);

        Assert.NotNull(principal);
        Assert.Equal("quantum-user", principal.FindFirst("sub")?.Value);
        Assert.Equal("enterprise", principal.FindFirst("tier")?.Value);
    }
}
