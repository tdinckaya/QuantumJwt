using System.Security.Cryptography;

namespace QuantumJwt;

/// <summary>
/// Configuration options for the QuantumJwt authentication setup.
/// </summary>
public sealed class QuantumJwtOptions
{
    /// <summary>
    /// The ML-DSA algorithm variant to use. Defaults to ML-DSA-65 (recommended).
    /// </summary>
    public MLDsaAlgorithm Algorithm { get; set; } = MLDsaAlgorithm.MLDsa65;

    /// <summary>The expected token issuer.</summary>
    public string? Issuer { get; set; }

    /// <summary>The expected token audience.</summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Raw ML-DSA private key bytes for signing tokens.
    /// If null, a key will be generated automatically.
    /// </summary>
    public byte[]? PrivateKeyBytes { get; set; }

    /// <summary>
    /// Raw ML-DSA public key bytes for verifying tokens.
    /// Required if <see cref="PrivateKeyBytes"/> is null and no key generation is desired.
    /// </summary>
    public byte[]? PublicKeyBytes { get; set; }

    /// <summary>
    /// Whether to validate token lifetime. Defaults to <c>true</c>.
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;
}

/// <summary>
/// Configuration options for the hybrid RSA → ML-DSA migration handler.
/// </summary>
public sealed class HybridMigrationOptions
{
    /// <summary>
    /// The legacy RSA or ECDSA key used to validate old tokens.
    /// </summary>
    public Microsoft.IdentityModel.Tokens.SecurityKey LegacyKey { get; set; } = null!;

    /// <summary>
    /// The new ML-DSA key used to sign refreshed tokens.
    /// </summary>
    public MlDsaSecurityKey NewKey { get; set; } = null!;

    /// <summary>
    /// The algorithm used by legacy tokens. Defaults to RS256.
    /// </summary>
    public string LegacyAlgorithm { get; set; } = Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256;

    /// <summary>
    /// The response header name for the refreshed ML-DSA token.
    /// Defaults to <c>X-Refreshed-Token</c>.
    /// </summary>
    public string ResponseHeaderName { get; set; } = "X-Refreshed-Token";

    /// <summary>
    /// Lifetime for newly generated ML-DSA tokens. Defaults to 1 hour.
    /// </summary>
    public TimeSpan NewTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// After this date, legacy tokens will be rejected entirely.
    /// Set this to enforce a migration deadline.
    /// <para>
    /// <b>Security recommendation:</b> Always set a sunset date.
    /// Open-ended migration windows are a security risk.
    /// </para>
    /// </summary>
    public DateTimeOffset? LegacyTokenSunsetDate { get; set; }

    /// <summary>
    /// The expected token issuer for legacy token validation.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The expected token audience for legacy token validation.
    /// </summary>
    public string? Audience { get; set; }
}
