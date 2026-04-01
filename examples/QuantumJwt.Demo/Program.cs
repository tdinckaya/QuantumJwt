#pragma warning disable SYSLIB5006

using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using QuantumJwt;

var builder = WebApplication.CreateBuilder(args);

// ── Key generation ───────────────────────────────────────────────
var mlDsaKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);

CompositeMlDsaSecurityKey? compositeKey = null;
if (CompositeMLDsa.IsSupported)
    compositeKey = CompositeMlDsaSecurityKey.Generate(CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);

// ── In-memory token blacklist ────────────────────────────────────
var blacklist = new ConcurrentDictionary<string, DateTimeOffset>();

// ── JWT authentication ───────────────────────────────────────────
builder.Services.AddQuantumJwt(mlDsaKey, bearer =>
{
    bearer.TokenValidationParameters.ValidIssuer = "QuantumJwt-Demo";
    bearer.TokenValidationParameters.ValidAudience = "demo-users";
});
builder.Services.AddAuthorization();

var app = builder.Build();

var tokenHandler = new JwtSecurityTokenHandler
{
    InboundClaimTypeMap = new Dictionary<string, string>()
};

// ── 1. GET / — Welcome + endpoint list ───────────────────────────
app.MapGet("/", () => Results.Json(new
{
    app = "QuantumJwt Demo",
    version = "1.0.1",
    algorithm = "ML-DSA-65",
    compositeSupported = CompositeMLDsa.IsSupported,
    endpoints = new Dictionary<string, string>
    {
        ["POST /token"] = "Generate ML-DSA signed JWT token",
        ["POST /token/composite"] = "Generate Composite ML-DSA token (RSA + quantum)",
        ["GET /protected"] = "Validate token and return claims",
        ["GET /token/analyze?token=xxx"] = "Analyze token size and infrastructure compatibility",
        ["POST /token/revoke"] = "Revoke a token (in-memory blacklist)",
        ["GET /token/revoked"] = "List all revoked tokens",
        ["GET /.well-known/jwks.json"] = "Public key discovery (JWK format)"
    }
}));

// ── 2. POST /token — Generate ML-DSA JWT ─────────────────────────
app.MapPost("/token", (JsonElement body) =>
{
    var claims = new List<Claim>();
    foreach (var prop in body.EnumerateObject())
    {
        claims.Add(new Claim(prop.Name, prop.Value.ToString()));
    }

    var jti = Guid.NewGuid().ToString();
    claims.Add(new Claim(JwtRegisteredClaimNames.Jti, jti));

    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(mlDsaKey, MlDsaAlgorithms.MlDsa65),
        Issuer = "QuantumJwt-Demo",
        Audience = "demo-users"
    };

    var tokenString = tokenHandler.CreateEncodedJwt(descriptor);
    var report = TokenCompression.AnalyzeTokenSize(tokenString);

    return Results.Json(new
    {
        token = tokenString,
        jti,
        algorithm = "ML-DSA-65",
        expiresIn = "1 hour",
        tokenSizeBytes = report.TotalBytes,
        warning = report.Warning
    });
});

// ── 3. POST /token/composite — Generate Composite ML-DSA JWT ─────
app.MapPost("/token/composite", (JsonElement body) =>
{
    if (compositeKey is null)
        return Results.Json(new { error = "Composite ML-DSA is not supported on this platform." }, statusCode: 501);

    var claims = new List<Claim>();
    foreach (var prop in body.EnumerateObject())
    {
        claims.Add(new Claim(prop.Name, prop.Value.ToString()));
    }

    var jti = Guid.NewGuid().ToString();
    claims.Add(new Claim(JwtRegisteredClaimNames.Jti, jti));

    var jwtAlg = MlDsaAlgorithms.ToJwtAlgorithm(compositeKey.Algorithm);

    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(compositeKey, jwtAlg),
        Issuer = "QuantumJwt-Demo",
        Audience = "demo-users"
    };

    var tokenString = tokenHandler.CreateEncodedJwt(descriptor);
    var report = TokenCompression.AnalyzeTokenSize(tokenString);

    return Results.Json(new
    {
        token = tokenString,
        jti,
        algorithm = jwtAlg,
        type = "composite",
        description = "Both RSA-4096 and ML-DSA-65 signatures in one token",
        tokenSizeBytes = report.TotalBytes,
        warning = report.Warning
    });
});

// ── 4. GET /protected — Validate token + blacklist check ─────────
app.MapGet("/protected", (HttpContext context) =>
{
    var authHeader = context.Request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Json(new { error = "Authorization header missing. Use: Authorization: Bearer <token>" }, statusCode: 401);
    }

    var tokenString = authHeader["Bearer ".Length..].Trim();

    try
    {
        var validationParams = new TokenValidationParameters
        {
            IssuerSigningKey = mlDsaKey,
            ValidIssuer = "QuantumJwt-Demo",
            ValidAudience = "demo-users",
            ValidateLifetime = true
        };

        var principal = tokenHandler.ValidateToken(tokenString, validationParams, out var validatedToken);
        var jwt = (JwtSecurityToken)validatedToken;

        // Check blacklist
        var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
        if (jti is not null && blacklist.TryGetValue(jti, out var revokedAt))
        {
            return Results.Json(new
            {
                error = "Token has been revoked",
                jti,
                revokedAt = revokedAt.ToString("O")
            }, statusCode: 401);
        }

        var claims = principal.Claims.ToDictionary(c => c.Type, c => c.Value);

        return Results.Json(new
        {
            message = "Token is valid! Post-quantum secure.",
            claims,
            algorithm = jwt.Header.Alg,
            keyId = jwt.Header.Kid
        });
    }
    catch (SecurityTokenException ex)
    {
        return Results.Json(new { error = "Token validation failed", detail = ex.Message }, statusCode: 401);
    }
});

// ── 5. GET /token/analyze — Token size analysis ──────────────────
app.MapGet("/token/analyze", (string token) =>
{
    try
    {
        var report = TokenCompression.AnalyzeTokenSize(token);
        return Results.Json(new
        {
            totalBytes = report.TotalBytes,
            headerBytes = report.HeaderBytes,
            payloadBytes = report.PayloadBytes,
            signatureBytes = report.SignatureBytes,
            authorizationHeaderBytes = report.AuthorizationHeaderBytes,
            warning = report.Warning,
            recommendation = report.Recommendation,
            infrastructure = new
            {
                nginx_4kb = report.AuthorizationHeaderBytes <= 4096 ? "OK" : "FAIL",
                apache_8kb = report.AuthorizationHeaderBytes <= 8192 ? "OK" : "FAIL",
                aws_alb_16kb = report.AuthorizationHeaderBytes <= 16384 ? "OK" : "FAIL",
                cloudflare_16kb = report.AuthorizationHeaderBytes <= 16384 ? "OK" : "FAIL"
            }
        });
    }
    catch (ArgumentException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

// ── 6. POST /token/revoke — Revoke a token ──────────────────────
app.MapPost("/token/revoke", (JsonElement body) =>
{
    if (!body.TryGetProperty("token", out var tokenProp))
        return Results.Json(new { error = "Missing 'token' field in request body" }, statusCode: 400);

    var tokenString = tokenProp.GetString();
    if (string.IsNullOrEmpty(tokenString))
        return Results.Json(new { error = "Token cannot be empty" }, statusCode: 400);

    try
    {
        var jwt = tokenHandler.ReadJwtToken(tokenString);
        var jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

        if (jti is null)
            return Results.Json(new { error = "Token does not contain a 'jti' claim. Cannot revoke." }, statusCode: 400);

        var now = DateTimeOffset.UtcNow;
        blacklist[jti] = now;

        return Results.Json(new
        {
            revoked = true,
            jti,
            revokedAt = now.ToString("O"),
            message = "Token will be rejected on all future requests"
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "Invalid token format", detail = ex.Message }, statusCode: 400);
    }
});

// ── 7. GET /token/revoked — List revoked tokens ──────────────────
app.MapGet("/token/revoked", () =>
{
    var tokens = blacklist.Select(kvp => new { jti = kvp.Key, revokedAt = kvp.Value.ToString("O") }).ToList();
    return Results.Json(new
    {
        totalRevoked = tokens.Count,
        tokens
    });
});

// ── 8. JWKS endpoint ─────────────────────────────────────────────
app.MapQuantumJwks();

app.Run();
