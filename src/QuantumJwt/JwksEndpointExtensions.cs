using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// Extension methods for exposing ML-DSA public keys via a JWKS endpoint.
/// </summary>
public static class JwksEndpointExtensions
{
    /// <summary>
    /// Maps a <c>/.well-known/jwks.json</c> endpoint that serves all active
    /// ML-DSA and Composite ML-DSA public keys in JWK format.
    /// <para>
    /// If <see cref="KeyRotationService"/> is registered, includes both the
    /// current signing key and any overlap-period validation keys.
    /// </para>
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="path">The endpoint path. Defaults to <c>/.well-known/jwks.json</c>.</param>
    public static IEndpointRouteBuilder MapQuantumJwks(
        this IEndpointRouteBuilder endpoints,
        string path = "/.well-known/jwks.json")
    {
        endpoints.MapGet(path, (HttpContext context) =>
        {
            var keys = new List<object>();

            // Check for KeyRotationService (has all active keys)
            var rotationService = context.RequestServices.GetService<KeyRotationService>();
            if (rotationService is not null)
            {
                foreach (var key in rotationService.AllValidationKeys)
                {
                    keys.Add(CreateJwk(key));
                }
            }
            else
            {
                // Fallback: check for individually registered keys
                var mlDsaKey = context.RequestServices.GetService<MlDsaSecurityKey>();
                if (mlDsaKey is not null)
                    keys.Add(CreateJwk(mlDsaKey));

                var compositeKey = context.RequestServices.GetService<CompositeMlDsaSecurityKey>();
                if (compositeKey is not null)
                    keys.Add(CreateCompositeJwk(compositeKey));
            }

            context.Response.Headers.CacheControl = "public, max-age=3600";
            context.Response.ContentType = "application/json";

            return Results.Json(new { keys });
        })
        .ExcludeFromDescription(); // Don't show in OpenAPI/Swagger

        return endpoints;
    }

    private static object CreateJwk(MlDsaSecurityKey key)
    {
        return new
        {
            kty = "ML-DSA",
            alg = MlDsaAlgorithms.ToJwtAlgorithm(key.Algorithm),
            kid = key.KeyId,
            use = "sig",
            x = Base64UrlEncoder.Encode(key.ExportPublicKey())
        };
    }

    private static object CreateCompositeJwk(CompositeMlDsaSecurityKey key)
    {
        return new
        {
            kty = "COMPOSITE",
            alg = MlDsaAlgorithms.ToJwtAlgorithm(key.Algorithm),
            kid = key.KeyId,
            use = "sig",
            x = Base64UrlEncoder.Encode(key.ExportPublicKey())
        };
    }
}
