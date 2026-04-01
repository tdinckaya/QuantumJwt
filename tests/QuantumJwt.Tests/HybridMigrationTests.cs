using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumJwt.Tests;

public class HybridMigrationTests
{
    private static readonly JwtSecurityTokenHandler TokenHandler = new()
    {
        InboundClaimTypeMap = new Dictionary<string, string>()
    };

    // ── Helper: create an RSA-signed token ───────────────────────

    private static (string Token, RsaSecurityKey RsaKey) CreateLegacyRsaToken(
        string issuer = "test",
        string audience = "test",
        TimeSpan? lifetime = null,
        IEnumerable<Claim>? claims = null)
    {
        var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims ?? new[]
            {
                new Claim("sub", "legacy-user"),
                new Claim("role", "admin")
            }),
            Expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromHours(1)),
            SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256),
            Issuer = issuer,
            Audience = audience
        };

        var token = TokenHandler.CreateEncodedJwt(descriptor);
        return (token, rsaKey);
    }

    // ── Helper: create migration handler ─────────────────────────

    private static (HybridMigrationHandler Handler, MlDsaSecurityKey NewKey) CreateHandler(
        RsaSecurityKey legacyKey,
        DateTimeOffset? sunsetDate = null)
    {
        var newKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
        var options = new HybridMigrationOptions
        {
            LegacyKey = legacyKey,
            NewKey = newKey,
            Issuer = "test",
            Audience = "test",
            LegacyTokenSunsetDate = sunsetDate
        };

        return (new HybridMigrationHandler(options), newKey);
    }

    // ── Helper: create a fake TokenValidatedContext ──────────────

    private static TokenValidatedContext CreateTokenValidatedContext(
        string tokenString,
        ClaimsPrincipal? principal = null)
    {
        var httpContext = new DefaultHttpContext();
        var jwt = TokenHandler.ReadJwtToken(tokenString);

        principal ??= new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims, "Bearer"));

        var scheme = new Microsoft.AspNetCore.Authentication.AuthenticationScheme(
            JwtBearerDefaults.AuthenticationScheme,
            JwtBearerDefaults.AuthenticationScheme,
            typeof(JwtBearerHandler));

        var context = new TokenValidatedContext(
            httpContext, scheme, new JwtBearerOptions())
        {
            SecurityToken = jwt,
            Principal = principal
        };

        return context;
    }

    // ── Helper: create a fake AuthenticationFailedContext ─────────

    private static AuthenticationFailedContext CreateAuthFailedContext(string tokenString)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {tokenString}";

        var scheme = new Microsoft.AspNetCore.Authentication.AuthenticationScheme(
            JwtBearerDefaults.AuthenticationScheme,
            JwtBearerDefaults.AuthenticationScheme,
            typeof(JwtBearerHandler));

        return new AuthenticationFailedContext(
            httpContext, scheme, new JwtBearerOptions())
        {
            Exception = new SecurityTokenValidationException("Simulated failure")
        };
    }

    // ── Tests ────────────────────────────────────────────────────

    [SkippableFact]
    public async Task LegacyRsaToken_OnTokenValidated_ReturnsRefreshedToken()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var (token, rsaKey) = CreateLegacyRsaToken();
        var (handler, newKey) = CreateHandler(rsaKey);

        var context = CreateTokenValidatedContext(token);
        await handler.OnTokenValidated(context);

        Assert.True(context.HttpContext.Response.Headers.ContainsKey("X-Refreshed-Token"));
        var refreshed = context.HttpContext.Response.Headers["X-Refreshed-Token"].ToString();
        Assert.NotEmpty(refreshed);

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task MlDsaToken_OnTokenValidated_NoRefreshHeader()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var mlDsaKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "quantum-user") }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(mlDsaKey, MlDsaAlgorithms.MlDsa65),
            Issuer = "test",
            Audience = "test"
        };

        var tokenString = TokenHandler.CreateEncodedJwt(descriptor);

        // Create a dummy legacy RSA key (won't be used)
        var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        var (handler, newKey) = CreateHandler(rsaKey);

        var context = CreateTokenValidatedContext(tokenString);
        await handler.OnTokenValidated(context);

        Assert.False(context.HttpContext.Response.Headers.ContainsKey("X-Refreshed-Token"));

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task InvalidRsaToken_OnAuthFailed_DoesNotSucceed()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        // Create a token with one RSA key, try to validate with a different one
        var (token, _) = CreateLegacyRsaToken();
        var differentRsa = RSA.Create(2048);
        var differentKey = new RsaSecurityKey(differentRsa);
        var (handler, newKey) = CreateHandler(differentKey);

        var context = CreateAuthFailedContext(token);
        await handler.OnAuthenticationFailed(context);

        // Should NOT have succeeded since the keys don't match
        Assert.Null(context.Result);

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task LegacyToken_OnAuthFailed_ValidatesAndRefreshes()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var (token, rsaKey) = CreateLegacyRsaToken();
        var (handler, newKey) = CreateHandler(rsaKey);

        var context = CreateAuthFailedContext(token);
        await handler.OnAuthenticationFailed(context);

        Assert.NotNull(context.Result);
        Assert.True(context.HttpContext.Response.Headers.ContainsKey("X-Refreshed-Token"));

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task RefreshedToken_IsValidMlDsa()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var (token, rsaKey) = CreateLegacyRsaToken();
        var (handler, newKey) = CreateHandler(rsaKey);

        var context = CreateTokenValidatedContext(token);
        await handler.OnTokenValidated(context);

        var refreshedToken = context.HttpContext.Response.Headers["X-Refreshed-Token"].ToString();

        // Validate the refreshed token with the ML-DSA key
        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = newKey,
            ValidIssuer = "test",
            ValidAudience = "test",
            ValidateLifetime = true
        };

        var principal = TokenHandler.ValidateToken(refreshedToken, validationParams, out var validatedToken);
        Assert.NotNull(principal);
        Assert.IsType<JwtSecurityToken>(validatedToken);

        var jwt = (JwtSecurityToken)validatedToken;
        Assert.Equal(MlDsaAlgorithms.MlDsa65, jwt.Header.Alg);

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task ClaimsArePreserved_DuringMigration()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var claims = new[]
        {
            new Claim("sub", "special-user"),
            new Claim("role", "admin"),
            new Claim("dept", "engineering")
        };

        var (token, rsaKey) = CreateLegacyRsaToken(claims: claims);
        var (handler, newKey) = CreateHandler(rsaKey);

        var context = CreateTokenValidatedContext(token);
        await handler.OnTokenValidated(context);

        var refreshedToken = context.HttpContext.Response.Headers["X-Refreshed-Token"].ToString();

        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = newKey,
            ValidIssuer = "test",
            ValidAudience = "test"
        };

        var principal = TokenHandler.ValidateToken(refreshedToken, validationParams, out _);

        Assert.Equal("special-user", principal.FindFirst("sub")?.Value);
        Assert.Equal("admin", principal.FindFirst("role")?.Value);
        Assert.Equal("engineering", principal.FindFirst("dept")?.Value);

        newKey.Dispose();
    }

    [SkippableFact]
    public async Task LegacyToken_AfterSunsetDate_IsRejected()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var (token, rsaKey) = CreateLegacyRsaToken();
        // Set sunset date in the past
        var (handler, newKey) = CreateHandler(rsaKey, sunsetDate: DateTimeOffset.UtcNow.AddDays(-1));

        // Test OnTokenValidated path
        var context = CreateTokenValidatedContext(token);
        await handler.OnTokenValidated(context);

        // Should have failed due to sunset
        Assert.NotNull(context.Result);
        Assert.False(context.Result!.Succeeded);

        // Test OnAuthenticationFailed path — should not attempt legacy validation
        var failedContext = CreateAuthFailedContext(token);
        await handler.OnAuthenticationFailed(failedContext);

        Assert.Null(failedContext.Result);
        Assert.False(failedContext.HttpContext.Response.Headers.ContainsKey("X-Refreshed-Token"));

        newKey.Dispose();
    }
}
