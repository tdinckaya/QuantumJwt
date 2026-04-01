# QuantumJwt

> **[Turkce dokumantasyon icin tiklayiniz](README.tr.md)**

Post-quantum JWT signing for .NET 10. Drop-in replacement — just change `IssuerSigningKey`.

[![NuGet](https://img.shields.io/nuget/v/QuantumJwt.svg)](https://www.nuget.org/packages/QuantumJwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tdinckaya/QuantumJwt)

## Try the Live Demo

```bash
# In GitHub Codespaces or any Linux/Windows machine with .NET 10:
cd examples/QuantumJwt.Demo && dotnet run

# Generate a token
curl -X POST http://localhost:5000/token -H "Content-Type: application/json" \
  -d '{"sub":"user1","role":"admin"}'

# Validate it
curl http://localhost:5000/protected -H "Authorization: Bearer <token>"

# Revoke it
curl -X POST http://localhost:5000/token/revoke -H "Content-Type: application/json" \
  -d '{"token":"<token>"}'
```

---

## What It Does

Bridges .NET 10's **ML-DSA (FIPS 204 / Dilithium)** and **Composite ML-DSA** post-quantum signature algorithms into the `Microsoft.IdentityModel.Tokens` JWT ecosystem.

**Before:**
```csharp
options.TokenValidationParameters = new()
{
    IssuerSigningKey = new RsaSecurityKey(rsa)
};
```

**After:**
```csharp
options.TokenValidationParameters = new()
{
    IssuerSigningKey = new MlDsaSecurityKey(mlDsaKey)
};
```

Everything else stays the same.

---

## Platform Requirements

| Platform | Minimum Version | Status |
|----------|----------------|--------|
| Windows | Windows 11 / Server 2025 | Supported |
| Linux | OpenSSL 3.5+ | Supported |
| macOS | — | Not supported |

> The library checks `MLDsa.IsSupported` at construction time and throws `PlatformNotSupportedException` with a clear message if the platform is unsupported.

---

## Installation

```bash
dotnet add package QuantumJwt
```

Requires **.NET 10** SDK.

---

## Quick Start

### 1. Pure ML-DSA (Simplest)

```csharp
using QuantumJwt;

// Program.cs
builder.Services.AddQuantumJwt(options =>
{
    options.Algorithm = MLDsaAlgorithm.MLDsa65;  // Recommended
    options.Issuer = "my-app";
    options.Audience = "my-app-users";
    // Auto-generates a key pair if PrivateKeyBytes is null
});
```

### 2. With Pre-existing Key

```csharp
var key = MlDsaSecurityKey.FromPrivateKey(
    File.ReadAllBytes("ml-dsa-private.key"),
    MLDsaAlgorithm.MLDsa65);

builder.Services.AddQuantumJwt(key, bearer =>
{
    bearer.TokenValidationParameters.ValidIssuer = "my-app";
    bearer.TokenValidationParameters.ValidAudience = "my-app-users";
});
```

### 3. Creating Tokens

```csharp
var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);
var handler = new JwtSecurityTokenHandler();

var token = handler.CreateEncodedJwt(new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(new[] { new Claim("sub", "user1") }),
    Expires = DateTime.UtcNow.AddHours(1),
    SigningCredentials = new SigningCredentials(key, MlDsaAlgorithms.MlDsa65),
    Issuer = "my-app"
});
```

---

## Composite ML-DSA (Hybrid Post-Quantum)

The strongest option for the transition period. Produces **both** a classical (RSA/ECDSA) and ML-DSA signature in the same token.

```csharp
using QuantumJwt;

var key = CompositeMlDsaSecurityKey.Generate(
    CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss);

builder.Services.AddCompositeQuantumJwt(key, bearer =>
{
    bearer.TokenValidationParameters.ValidIssuer = "my-app";
    bearer.TokenValidationParameters.ValidAudience = "my-app-users";
});
```

### Available Composite Algorithms

| Algorithm | Classical Component | Quantum Component |
|-----------|-------------------|-------------------|
| `MLDsa44WithECDsaP256` | ECDSA P-256 | ML-DSA-44 |
| `MLDsa44WithRSA2048Pss` | RSA-2048 PSS | ML-DSA-44 |
| `MLDsa65WithECDsaP384` | ECDSA P-384 | ML-DSA-65 |
| `MLDsa65WithRSA4096Pss` | RSA-4096 PSS | ML-DSA-65 |
| `MLDsa87WithECDsaP384` | ECDSA P-384 | ML-DSA-87 |
| `MLDsa87WithECDsaP521` | ECDSA P-521 | ML-DSA-87 |

### Composite vs Pure ML-DSA

| | Pure ML-DSA | Composite ML-DSA |
|---|---|---|
| **Quantum-safe** | Yes | Yes |
| **Classical-safe** | No fallback | Yes (dual signature) |
| **Token size** | ~3-5 KB | ~5-8 KB |
| **Best for** | Green-field apps | Migration, regulated environments |

---

## Hybrid Migration (RSA → ML-DSA)

Transparently convert legacy RSA tokens to ML-DSA tokens without breaking existing clients.

```csharp
var legacyRsaKey = new RsaSecurityKey(RSA.Create(2048));
var newMlDsaKey = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);

builder.Services
    .AddQuantumJwt(newMlDsaKey)
    .AddHybridMigration(options =>
    {
        options.LegacyKey = legacyRsaKey;
        options.NewKey = newMlDsaKey;
        options.Issuer = "my-app";
        options.Audience = "my-app-users";

        // IMPORTANT: Set a sunset date!
        options.LegacyTokenSunsetDate = new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero);
    });
```

### How It Works

1. Client sends `Authorization: Bearer <RSA-token>`
2. Server validates with legacy RSA key
3. Server generates a new ML-DSA token with the same claims
4. Response includes `X-Refreshed-Token: <ML-DSA-token>`
5. Client switches to the new token on next request
6. After `LegacyTokenSunsetDate`, old tokens are rejected

### Migration Timeline

```
Day 0:  Deploy with AddHybridMigration()
        Both RSA and ML-DSA tokens accepted
        ↓
Day 1+: Clients receive X-Refreshed-Token header
        Clients switch to ML-DSA tokens
        ↓
Sunset: LegacyTokenSunsetDate reached
        Only ML-DSA tokens accepted
        ↓
Final:  Remove AddHybridMigration(), keep only AddQuantumJwt()
```

---

## Key Management

### Automatic Key Rotation

Built-in `KeyRotationService` runs as a background `IHostedService`:

```csharp
builder.Services
    .AddQuantumJwt(key)
    .AddKeyRotation(options =>
    {
        options.Algorithm = MLDsaAlgorithm.MLDsa65;
        options.RotationInterval = TimeSpan.FromDays(90);   // Generate new key every 90 days
        options.KeyOverlapPeriod = TimeSpan.FromDays(7);    // Keep old key valid for 7 days
        options.KeyStore = new FileKeyStore("/keys", Environment.GetEnvironmentVariable("KEY_PASSWORD")!);

        options.OnKeyRotated = async newKey =>
        {
            Console.WriteLine($"New key: {newKey.KeyId}");
            // Notify external systems, update Key Vault, etc.
        };

        options.OnKeyRetired = async oldKey =>
        {
            Console.WriteLine($"Key retired: {oldKey.KeyId}");
        };
    });
```

**How it works:**

```
Day 0:   Key A generated (signing + verification)
Day 90:  Key B generated (signing), Key A still valid (verification only)
Day 97:  Key A retired, Key B is the only active key
Day 180: Key C generated, Key B moves to overlap...
```

Access the current key for token creation:

```csharp
app.MapPost("/token", (KeyRotationService rotation) =>
{
    var key = rotation.CurrentSigningKey;
    var handler = new JwtSecurityTokenHandler();
    // ... create token with key
});
```

### JWKS Endpoint

Built-in `/.well-known/jwks.json` endpoint:

```csharp
app.MapQuantumJwks(); // That's it!
```

Automatically serves all active public keys in JWK format. If `KeyRotationService` is registered, includes both current and overlap-period keys. Sets `Cache-Control: public, max-age=3600`.

**Response format:**
```json
{
  "keys": [{
    "kty": "ML-DSA",
    "alg": "ML-DSA-65",
    "kid": "abc123...",
    "use": "sig",
    "x": "<base64url-encoded-public-key>"
  }]
}
```

### Key Storage

**`IKeyStore` interface** — implement for your infrastructure:

```csharp
public interface IKeyStore
{
    Task<byte[]?> LoadPrivateKeyAsync(string keyId);
    Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey);
    Task DeleteKeyAsync(string keyId);
    Task<IReadOnlyList<string>> ListKeyIdsAsync();
}
```

**Built-in `FileKeyStore`** — encrypted PKCS#8 files (AES-256-CBC, 100K PBKDF2 iterations):

```csharp
var store = new FileKeyStore("/secure/keys", password);

// Encrypt and save
var encrypted = store.EncryptKey(key);
await store.SavePrivateKeyAsync(key.KeyId, encrypted);

// Load and decrypt
var loaded = await store.LoadPrivateKeyAsync(keyId);
var restoredKey = store.DecryptKey(loaded!, MLDsaAlgorithm.MLDsa65);
```

**For production**, implement `IKeyStore` with:
- Azure Key Vault
- AWS KMS
- HashiCorp Vault
- Hardware Security Modules (HSM)

**Do NOT** store private keys in source code, environment variables, or plain text files.

---

## Token Size Warning

ML-DSA signatures are significantly larger than RSA:

| Algorithm | Signature Size | Typical JWT Size |
|-----------|---------------|-----------------|
| RS256 | 256 bytes | ~800 bytes |
| ML-DSA-44 | 2,420 bytes | ~3.5 KB |
| ML-DSA-65 | 3,293 bytes | ~4.8 KB |
| ML-DSA-87 | 4,595 bytes | ~6.2 KB |
| Composite (ML-DSA-65 + RSA-4096) | ~3,800 bytes | ~5.5 KB |

### Potential Issues & Solutions

| System | Default Header Limit | Impact |
|--------|---------------------|--------|
| Nginx | 4 KB | Will break with ML-DSA-65+ |
| Apache | 8 KB | May break with ML-DSA-87 |
| AWS ALB | 16 KB | Safe |
| Cloudflare | 16 KB | Safe |

**Nginx fix:**
```nginx
large_client_header_buffers 4 16k;
```

**Kestrel fix:**
```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestHeadersTotalSize = 32768;
});
```

### Token Size Analysis

Built-in `TokenCompression.AnalyzeTokenSize()` tells you exactly which systems will break:

```csharp
var report = TokenCompression.AnalyzeTokenSize(jwt);
Console.WriteLine(report);
// Token: 4832 bytes (header:42 payload:198 sig:4590) | Auth header: 4839 bytes
// | Exceeds Nginx default header limit (4KB).

Console.WriteLine(report.Warning);         // "Exceeds Nginx default header limit (4KB)."
Console.WriteLine(report.Recommendation);  // "Nginx: large_client_header_buffers 4 16k;"
```

### Token Compression

DEFLATE compression for large payloads:

```csharp
var compressed = TokenCompression.CompressToken(jwt);
var original = TokenCompression.DecompressToken(compressed);
```

> **Note:** Compressed tokens must be decompressed before standard JWT validation. The signature covers the original payload.

---

## Security Warnings

1. **Experimental API**: ML-DSA support in .NET 10 is marked `[Experimental]` (`SYSLIB5006`). The API may change before GA.

2. **FIPS 204**: ML-DSA implements FIPS 204 (Dilithium). It is standardized by NIST but quantum computer capabilities are still theoretical.

3. **Timing side-channel**: The `OnAuthenticationFailed` handler in hybrid migration retries validation with the legacy key. This is not constant-time. For high-security environments, use `IssuerSigningKeys` with both keys instead of the migration handler.

4. **Set a sunset date**: Always configure `LegacyTokenSunsetDate` when using hybrid migration. Open-ended migration windows are a security risk.

5. **Token size**: Post-quantum signatures are 10-20x larger than RSA. Test your infrastructure (proxies, load balancers, CDNs) before deploying.

---

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `MlDsaSecurityKey` | `AsymmetricSecurityKey` wrapper for ML-DSA keys |
| `CompositeMlDsaSecurityKey` | `AsymmetricSecurityKey` wrapper for Composite ML-DSA keys |
| `MlDsaSignatureProvider` | `SignatureProvider` for ML-DSA Sign/Verify |
| `CompositeMlDsaSignatureProvider` | `SignatureProvider` for Composite ML-DSA Sign/Verify |
| `MlDsaCryptoProvider` | `ICryptoProvider` factory (auto-configured) |
| `MlDsaAlgorithms` | Algorithm identifier constants |
| `KeyRotationService` | `IHostedService` for automatic key rotation |
| `FileKeyStore` | Encrypted file-based `IKeyStore` implementation |
| `TokenCompression` | Token size analysis and DEFLATE compression |
| `TokenSizeReport` | Infrastructure compatibility report |

### Interfaces

| Interface | Description |
|-----------|-------------|
| `IKeyStore` | Key persistence abstraction (implement for Key Vault, KMS, etc.) |

### Extension Methods

| Method | Description |
|--------|-------------|
| `AddQuantumJwt(options)` | Configure JWT with ML-DSA via options |
| `AddQuantumJwt(key, configure?)` | Configure JWT with a pre-made ML-DSA key |
| `AddCompositeQuantumJwt(key, configure?)` | Configure JWT with a Composite ML-DSA key |
| `AddHybridMigration(options)` | Add RSA→ML-DSA transparent migration |
| `AddKeyRotation(options)` | Add automatic key rotation as background service |
| `MapQuantumJwks(path?)` | Map JWKS endpoint for public key discovery |

---

## License

MIT
