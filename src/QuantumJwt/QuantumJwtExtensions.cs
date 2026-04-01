using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// Extension methods for integrating QuantumJwt into the ASP.NET Core
/// authentication pipeline.
/// </summary>
public static class QuantumJwtExtensions
{
    /// <summary>
    /// Adds JWT Bearer authentication with ML-DSA post-quantum signing.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure <see cref="QuantumJwtOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for further chaining.</returns>
    public static AuthenticationBuilder AddQuantumJwt(
        this IServiceCollection services,
        Action<QuantumJwtOptions> configure)
    {
        var options = new QuantumJwtOptions();
        configure(options);

        var key = CreateKeyFromOptions(options);

        // Register the key as a singleton so it can be injected for token creation
        services.AddSingleton(key);

        return services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(bearer =>
            {
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = key,
                    ValidIssuer = options.Issuer,
                    ValidAudience = options.Audience,
                    ValidateLifetime = options.ValidateLifetime,
                    ValidateIssuer = options.Issuer is not null,
                    ValidateAudience = options.Audience is not null,
                    ValidateIssuerSigningKey = true
                };
            });
    }

    /// <summary>
    /// Adds JWT Bearer authentication with a pre-configured <see cref="MlDsaSecurityKey"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="signingKey">The ML-DSA security key.</param>
    /// <param name="configureBearer">Optional additional JWT Bearer configuration.</param>
    public static AuthenticationBuilder AddQuantumJwt(
        this IServiceCollection services,
        MlDsaSecurityKey signingKey,
        Action<JwtBearerOptions>? configureBearer = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);

        services.AddSingleton(signingKey);

        return services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(bearer =>
            {
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = signingKey,
                    ValidateIssuerSigningKey = true
                };

                configureBearer?.Invoke(bearer);
            });
    }

    /// <summary>
    /// Adds JWT Bearer authentication with a pre-configured <see cref="CompositeMlDsaSecurityKey"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="compositeKey">The composite ML-DSA security key.</param>
    /// <param name="configureBearer">Optional additional JWT Bearer configuration.</param>
    public static AuthenticationBuilder AddCompositeQuantumJwt(
        this IServiceCollection services,
        CompositeMlDsaSecurityKey compositeKey,
        Action<JwtBearerOptions>? configureBearer = null)
    {
        ArgumentNullException.ThrowIfNull(compositeKey);

        services.AddSingleton(compositeKey);

        return services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(bearer =>
            {
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = compositeKey,
                    ValidateIssuerSigningKey = true
                };

                configureBearer?.Invoke(bearer);
            });
    }

    /// <summary>
    /// Adds hybrid migration support that transparently converts legacy RSA/ECDSA
    /// tokens into ML-DSA tokens via the <c>X-Refreshed-Token</c> response header.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configure">Action to configure <see cref="HybridMigrationOptions"/>.</param>
    public static AuthenticationBuilder AddHybridMigration(
        this AuthenticationBuilder builder,
        Action<HybridMigrationOptions> configure)
    {
        var options = new HybridMigrationOptions();
        configure(options);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<HybridMigrationHandler>();

        // Configure JWT Bearer events to intercept legacy tokens
        builder.Services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            bearer =>
            {
                var handler = new HybridMigrationHandler(options);
                var existingEvents = bearer.Events ?? new JwtBearerEvents();

                var originalOnTokenValidated = existingEvents.OnTokenValidated;
                existingEvents.OnTokenValidated = async context =>
                {
                    await handler.OnTokenValidated(context);
                    if (originalOnTokenValidated is not null)
                        await originalOnTokenValidated(context);
                };

                var originalOnAuthFailed = existingEvents.OnAuthenticationFailed;
                existingEvents.OnAuthenticationFailed = async context =>
                {
                    await handler.OnAuthenticationFailed(context);
                    if (originalOnAuthFailed is not null)
                        await originalOnAuthFailed(context);
                };

                bearer.Events = existingEvents;

                // Add legacy key as a valid issuer signing key so JWT middleware
                // can validate both old and new tokens
                var tvp = bearer.TokenValidationParameters;
                if (tvp.IssuerSigningKeys is null)
                {
                    tvp.IssuerSigningKeys = new[] { tvp.IssuerSigningKey!, options.LegacyKey };
                }
                else
                {
                    tvp.IssuerSigningKeys = tvp.IssuerSigningKeys.Append(options.LegacyKey);
                }
            });

        return builder;
    }

    /// <summary>
    /// Adds automatic ML-DSA key rotation as a background service.
    /// <para>
    /// The service generates a new key every <see cref="KeyRotationOptions.RotationInterval"/>,
    /// keeps old keys valid for <see cref="KeyRotationOptions.KeyOverlapPeriod"/>,
    /// and automatically updates <see cref="TokenValidationParameters.IssuerSigningKeys"/>.
    /// </para>
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configure">Action to configure <see cref="KeyRotationOptions"/>.</param>
    public static AuthenticationBuilder AddKeyRotation(
        this AuthenticationBuilder builder,
        Action<KeyRotationOptions> configure)
    {
        var options = new KeyRotationOptions();
        configure(options);

        var service = new KeyRotationService(options);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(service);
        builder.Services.AddHostedService(sp => sp.GetRequiredService<KeyRotationService>());

        // Wire up dynamic key resolution
        builder.Services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            bearer =>
            {
                bearer.TokenValidationParameters.IssuerSigningKeyResolver =
                    (token, securityToken, kid, validationParameters) =>
                    {
                        return service.AllValidationKeys;
                    };
            });

        return builder;
    }

    // ── Private helpers ──────────────────────────────────────────

    private static MlDsaSecurityKey CreateKeyFromOptions(QuantumJwtOptions options)
    {
        if (options.PrivateKeyBytes is not null)
            return MlDsaSecurityKey.FromPrivateKey(options.PrivateKeyBytes, options.Algorithm);

        if (options.PublicKeyBytes is not null)
            return MlDsaSecurityKey.FromPublicKey(options.PublicKeyBytes, options.Algorithm);

        // Auto-generate a new key pair
        return MlDsaSecurityKey.Generate(options.Algorithm);
    }
}
