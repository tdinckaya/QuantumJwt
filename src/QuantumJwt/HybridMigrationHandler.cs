using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// Handles transparent migration from legacy RSA/ECDSA JWT tokens to ML-DSA tokens.
/// <para>
/// When a legacy token arrives:
/// <list type="number">
///   <item>The token is validated using the legacy key.</item>
///   <item>A new ML-DSA token is generated with the same claims.</item>
///   <item>The new token is returned in the <c>X-Refreshed-Token</c> response header.</item>
///   <item>The client can switch to the new token transparently.</item>
/// </list>
/// </para>
/// <para>
/// <b>Security note:</b> The <c>OnAuthenticationFailed</c> handler retries validation
/// with the legacy key. This creates a timing side-channel. For high-security
/// environments, consider validating both keys upfront via
/// <see cref="TokenValidationParameters.IssuerSigningKeys"/> instead.
/// </para>
/// </summary>
public sealed class HybridMigrationHandler
{
    private readonly HybridMigrationOptions _options;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    /// <summary>
    /// Initializes a new <see cref="HybridMigrationHandler"/>.
    /// </summary>
    public HybridMigrationHandler(HybridMigrationOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Called after a token has been successfully validated.
    /// If the token uses a legacy algorithm, generates a refreshed ML-DSA token.
    /// </summary>
    internal async Task OnTokenValidated(TokenValidatedContext context)
    {
        if (context.SecurityToken is not JwtSecurityToken jwt)
            return;

        var alg = jwt.Header.Alg;

        // If already using an ML-DSA algorithm, nothing to do
        if (MlDsaAlgorithms.All.Contains(alg))
            return;

        // Check sunset date — after this, legacy tokens should have been migrated
        if (_options.LegacyTokenSunsetDate.HasValue &&
            DateTimeOffset.UtcNow > _options.LegacyTokenSunsetDate.Value)
        {
            context.Fail("Legacy token migration period has expired. " +
                         $"Sunset date was {_options.LegacyTokenSunsetDate.Value:O}.");
            return;
        }

        // Generate a new ML-DSA token with the same claims
        var refreshedToken = GenerateRefreshedToken(context.Principal!);

        // Add the refreshed token to the response header
        context.HttpContext.Response.Headers[_options.ResponseHeaderName] = refreshedToken;

        await Task.CompletedTask;
    }

    /// <summary>
    /// Called when token validation fails. Attempts to validate the token
    /// using the legacy key if the primary (ML-DSA) validation failed.
    /// </summary>
    internal async Task OnAuthenticationFailed(AuthenticationFailedContext context)
    {
        // Only attempt legacy validation if we haven't already handled it
        if (context.Result is not null)
            return;

        // Check sunset date first — don't even try legacy validation after sunset
        if (_options.LegacyTokenSunsetDate.HasValue &&
            DateTimeOffset.UtcNow > _options.LegacyTokenSunsetDate.Value)
            return;

        // Try to extract the token from the Authorization header
        var authHeader = context.HttpContext.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return;

        var tokenString = authHeader["Bearer ".Length..].Trim();

        try
        {
            var legacyValidationParams = new TokenValidationParameters
            {
                IssuerSigningKey = _options.LegacyKey,
                ValidAlgorithms = new[] { _options.LegacyAlgorithm },
                ValidIssuer = _options.Issuer,
                ValidAudience = _options.Audience,
                ValidateIssuer = _options.Issuer is not null,
                ValidateAudience = _options.Audience is not null,
                ValidateLifetime = true
            };

            var principal = _tokenHandler.ValidateToken(tokenString, legacyValidationParams, out _);

            // Legacy validation succeeded — generate a refreshed ML-DSA token
            var refreshedToken = GenerateRefreshedToken(principal);
            context.HttpContext.Response.Headers[_options.ResponseHeaderName] = refreshedToken;

            // Set the principal so the request continues as authenticated
            context.Principal = principal;
            context.Success();
        }
        catch (SecurityTokenException)
        {
            // Legacy validation also failed — let the original error stand
        }

        await Task.CompletedTask;
    }

    // ── Private helpers ──────────────────────────────────────────

    private string GenerateRefreshedToken(ClaimsPrincipal principal)
    {
        var jwtAlgorithm = MlDsaAlgorithms.ToJwtAlgorithm(_options.NewKey.Algorithm);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(principal.Claims),
            Expires = DateTime.UtcNow.Add(_options.NewTokenLifetime),
            SigningCredentials = new SigningCredentials(_options.NewKey, jwtAlgorithm),
            Issuer = _options.Issuer,
            Audience = _options.Audience
        };

        return _tokenHandler.CreateEncodedJwt(descriptor);
    }
}
