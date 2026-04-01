# QuantumJwt

> **[Click here for English documentation](README.md)**

.NET 10 icin post-quantum JWT imzalama. Sadece `IssuerSigningKey` satirini degistirin, gerisi ayni kalsin.

[![NuGet](https://img.shields.io/nuget/v/QuantumJwt.svg)](https://www.nuget.org/packages/QuantumJwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Ne Yapar?

.NET 10'un **ML-DSA (FIPS 204 / Dilithium)** ve **Composite ML-DSA** post-quantum imza algoritmalarini `Microsoft.IdentityModel.Tokens` JWT ekosistemine baglar.

**Oncesi:**
```csharp
options.TokenValidationParameters = new()
{
    IssuerSigningKey = new RsaSecurityKey(rsa)
};
```

**Sonrasi:**
```csharp
options.TokenValidationParameters = new()
{
    IssuerSigningKey = new MlDsaSecurityKey(mlDsaKey)
};
```

Baska hicbir sey degismiyor.

---

## Platform Gereksinimleri

| Platform | Minimum Surum | Durum |
|----------|--------------|-------|
| Windows | Windows 11 / Server 2025 | Destekleniyor |
| Linux | OpenSSL 3.5+ | Destekleniyor |
| macOS | — | Desteklenmiyor |

> Kutuphane olusturma aninda `MLDsa.IsSupported` kontrolu yapar. Desteklenmeyen platformda net bir `PlatformNotSupportedException` firlatir.

---

## Kurulum

```bash
dotnet add package QuantumJwt
```

**.NET 10** SDK gerektirir.

---

## Hizli Baslangic

### 1. Saf ML-DSA (En Basit)

```csharp
using QuantumJwt;

// Program.cs
builder.Services.AddQuantumJwt(options =>
{
    options.Algorithm = MLDsaAlgorithm.MLDsa65;  // Onerilen
    options.Issuer = "my-app";
    options.Audience = "my-app-users";
    // PrivateKeyBytes null ise otomatik anahtar cifti olusturur
});
```

### 2. Mevcut Anahtar ile

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

### 3. Token Olusturma

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

## Composite ML-DSA (Hibrit Post-Quantum)

Gecis donemi icin en guclu secenek. Ayni token'da hem klasik (RSA/ECDSA) hem ML-DSA imzasi uretir.

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

### Mevcut Composite Algoritmalari

| Algoritma | Klasik Bilesen | Quantum Bilesen |
|-----------|---------------|-----------------|
| `MLDsa44WithECDsaP256` | ECDSA P-256 | ML-DSA-44 |
| `MLDsa44WithRSA2048Pss` | RSA-2048 PSS | ML-DSA-44 |
| `MLDsa65WithECDsaP384` | ECDSA P-384 | ML-DSA-65 |
| `MLDsa65WithRSA4096Pss` | RSA-4096 PSS | ML-DSA-65 |
| `MLDsa87WithECDsaP384` | ECDSA P-384 | ML-DSA-87 |
| `MLDsa87WithECDsaP521` | ECDSA P-521 | ML-DSA-87 |

### Composite vs Saf ML-DSA

| | Saf ML-DSA | Composite ML-DSA |
|---|---|---|
| **Quantum-guvenli** | Evet | Evet |
| **Klasik-guvenli** | Fallback yok | Evet (cift imza) |
| **Token boyutu** | ~3-5 KB | ~5-8 KB |
| **En uygun** | Sifirdan projeler | Goc, regule ortamlar |

---

## Hibrit Goc (RSA -> ML-DSA)

Eski RSA token'lari seffaf sekilde ML-DSA token'larina donusturur. Istemciler hicbir sey farketmez.

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

        // ONEMLI: Mutlaka bir bitis tarihi belirleyin!
        options.LegacyTokenSunsetDate = new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero);
    });
```

### Nasil Calisir?

1. Istemci `Authorization: Bearer <RSA-token>` gonderir
2. Sunucu eski RSA anahtariyla dogrular
3. Sunucu ayni claim'lerle yeni ML-DSA token uretir
4. Yanit `X-Refreshed-Token: <ML-DSA-token>` header'i icerir
5. Istemci bir sonraki istekte yeni token'i kullanir
6. `LegacyTokenSunsetDate` sonrasi eski token'lar reddedilir

### Goc Zaman Cizelgesi

```
Gun 0:   AddHybridMigration() ile deploy
         Hem RSA hem ML-DSA token'lar kabul edilir
         |
Gun 1+:  Istemciler X-Refreshed-Token header'i alir
         Istemciler ML-DSA token'a gecer
         |
Bitis:   LegacyTokenSunsetDate'e ulasilir
         Sadece ML-DSA token'lar kabul edilir
         |
Son:     AddHybridMigration() kaldirilir, sadece AddQuantumJwt() kalir
```

---

## Anahtar Yonetimi

### Otomatik Anahtar Rotasyonu

Dahili `KeyRotationService` arka plan `IHostedService` olarak calisir:

```csharp
builder.Services
    .AddQuantumJwt(key)
    .AddKeyRotation(options =>
    {
        options.Algorithm = MLDsaAlgorithm.MLDsa65;
        options.RotationInterval = TimeSpan.FromDays(90);   // Her 90 gunde yeni anahtar
        options.KeyOverlapPeriod = TimeSpan.FromDays(7);    // Eski anahtari 7 gun gecerli tut
        options.KeyStore = new FileKeyStore("/keys", Environment.GetEnvironmentVariable("KEY_PASSWORD")!);

        options.OnKeyRotated = async newKey =>
        {
            Console.WriteLine($"Yeni anahtar: {newKey.KeyId}");
            // Dis sistemleri bilgilendir, Key Vault'u guncelle vb.
        };

        options.OnKeyRetired = async oldKey =>
        {
            Console.WriteLine($"Anahtar emekli: {oldKey.KeyId}");
        };
    });
```

**Nasil calisir:**

```
Gun 0:   Anahtar A uretilir (imzalama + dogrulama)
Gun 90:  Anahtar B uretilir (imzalama), Anahtar A hala gecerli (sadece dogrulama)
Gun 97:  Anahtar A emekli edilir, Anahtar B tek aktif anahtar
Gun 180: Anahtar C uretilir, Anahtar B overlap'e gecer...
```

Token olusturmak icin guncel anahtara erisim:

```csharp
app.MapPost("/token", (KeyRotationService rotation) =>
{
    var key = rotation.CurrentSigningKey;
    var handler = new JwtSecurityTokenHandler();
    // ... key ile token olustur
});
```

### JWKS Endpoint

Dahili `/.well-known/jwks.json` endpoint'i:

```csharp
app.MapQuantumJwks(); // Bu kadar!
```

Tum aktif public key'leri JWK formatinda sunar. `KeyRotationService` kayitliysa hem guncel hem overlap donemindeki key'leri dahil eder. `Cache-Control: public, max-age=3600` header'i set eder.

**Yanit formati:**
```json
{
  "keys": [{
    "kty": "ML-DSA",
    "alg": "ML-DSA-65",
    "kid": "abc123...",
    "use": "sig",
    "x": "<base64url-kodlanmis-public-key>"
  }]
}
```

### Anahtar Saklama

**`IKeyStore` arayuzu** — kendi altyapiniz icin implement edin:

```csharp
public interface IKeyStore
{
    Task<byte[]?> LoadPrivateKeyAsync(string keyId);
    Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey);
    Task DeleteKeyAsync(string keyId);
    Task<IReadOnlyList<string>> ListKeyIdsAsync();
}
```

**Dahili `FileKeyStore`** — sifrelenmis PKCS#8 dosyalari (AES-256-CBC, 100K PBKDF2 iterasyon):

```csharp
var store = new FileKeyStore("/secure/keys", password);

// Sifrele ve kaydet
var encrypted = store.EncryptKey(key);
await store.SavePrivateKeyAsync(key.KeyId, encrypted);

// Yukle ve coz
var loaded = await store.LoadPrivateKeyAsync(keyId);
var restoredKey = store.DecryptKey(loaded!, MLDsaAlgorithm.MLDsa65);
```

**Production icin** `IKeyStore`'u su servislerle implement edin:
- Azure Key Vault
- AWS KMS
- HashiCorp Vault
- Hardware Security Modules (HSM)

Ozel anahtarlari kaynak kodda, ortam degiskenlerinde veya duz metin dosyalarinda **SAKLAMAYIN**.

---

## Token Boyutu Uyarisi

ML-DSA imzalari RSA'dan onemli olcude buyuktur:

| Algoritma | Imza Boyutu | Tipik JWT Boyutu |
|-----------|------------|-----------------|
| RS256 | 256 byte | ~800 byte |
| ML-DSA-44 | 2.420 byte | ~3.5 KB |
| ML-DSA-65 | 3.293 byte | ~4.8 KB |
| ML-DSA-87 | 4.595 byte | ~6.2 KB |
| Composite (ML-DSA-65 + RSA-4096) | ~3.800 byte | ~5.5 KB |

### Olasi Sorunlar ve Cozumler

| Sistem | Varsayilan Header Limiti | Etki |
|--------|------------------------|------|
| Nginx | 4 KB | ML-DSA-65+ ile bozulur |
| Apache | 8 KB | ML-DSA-87 ile bozulabilir |
| AWS ALB | 16 KB | Guvenli |
| Cloudflare | 16 KB | Guvenli |

**Nginx duzeltmesi:**
```nginx
large_client_header_buffers 4 16k;
```

**Kestrel duzeltmesi:**
```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestHeadersTotalSize = 32768;
});
```

### Token Boyut Analizi

Dahili `TokenCompression.AnalyzeTokenSize()` hangi sistemlerin bozulacagini soyler:

```csharp
var report = TokenCompression.AnalyzeTokenSize(jwt);
Console.WriteLine(report);
// Token: 4832 bytes (header:42 payload:198 sig:4590) | Auth header: 4839 bytes
// | Exceeds Nginx default header limit (4KB).

Console.WriteLine(report.Warning);         // "Exceeds Nginx default header limit (4KB)."
Console.WriteLine(report.Recommendation);  // "Nginx: large_client_header_buffers 4 16k;"
```

### Token Sikistirma

Buyuk payload'lar icin DEFLATE sikistirma:

```csharp
var compressed = TokenCompression.CompressToken(jwt);
var original = TokenCompression.DecompressToken(compressed);
```

> **Not:** Sikistirilmis token'lar standart JWT dogrulamasindan once acilmalidir. Imza orijinal payload'i kapsar.

---

## Guvenlik Uyarilari

1. **Deneysel API**: .NET 10'daki ML-DSA destegi `[Experimental]` (`SYSLIB5006`) olarak isaretlenmistir. API, GA oncesinde degisebilir.

2. **FIPS 204**: ML-DSA, FIPS 204 (Dilithium) standardini uygular. NIST tarafindan standartlastirilmistir ancak quantum bilgisayar yetenekleri hala teoriktir.

3. **Zamanlama yan kanali**: Hibrit gocun `OnAuthenticationFailed` handler'i eski anahtarla dogrulamayi yeniden dener. Bu sabit zamanli degildir. Yuksek guvenlikli ortamlar icin goc handler'i yerine her iki anahtarla `IssuerSigningKeys` kullanin.

4. **Bitis tarihi belirleyin**: Hibrit goc kullanirken her zaman `LegacyTokenSunsetDate` yapilandirin. Acik uclu goc pencereleri guvenlik riskidir.

5. **Token boyutu**: Post-quantum imzalar RSA'dan 10-20x buyuktur. Deploy etmeden once altyapinizi (proxy'ler, yuk dengeleyiciler, CDN'ler) test edin.

---

## API Referansi

### Temel Siniflar

| Sinif | Aciklama |
|-------|---------|
| `MlDsaSecurityKey` | ML-DSA anahtarlari icin `AsymmetricSecurityKey` wrapper |
| `CompositeMlDsaSecurityKey` | Composite ML-DSA anahtarlari icin `AsymmetricSecurityKey` wrapper |
| `MlDsaSignatureProvider` | ML-DSA Sign/Verify icin `SignatureProvider` |
| `CompositeMlDsaSignatureProvider` | Composite ML-DSA Sign/Verify icin `SignatureProvider` |
| `MlDsaCryptoProvider` | `ICryptoProvider` fabrikasi (otomatik yapilandirilir) |
| `MlDsaAlgorithms` | Algoritma tanimlayici sabitleri |
| `KeyRotationService` | Otomatik anahtar rotasyonu icin `IHostedService` |
| `FileKeyStore` | Sifrelenmis dosya tabanli `IKeyStore` uygulamasi |
| `TokenCompression` | Token boyut analizi ve DEFLATE sikistirma |
| `TokenSizeReport` | Altyapi uyumluluk raporu |

### Arayuzler

| Arayuz | Aciklama |
|--------|---------|
| `IKeyStore` | Anahtar kalicilik soyutlamasi (Key Vault, KMS vb. icin implement edin) |

### Extension Metodlar

| Metod | Aciklama |
|-------|---------|
| `AddQuantumJwt(options)` | ML-DSA ile JWT yapilandir |
| `AddQuantumJwt(key, configure?)` | Hazir ML-DSA anahtariyla JWT yapilandir |
| `AddCompositeQuantumJwt(key, configure?)` | Composite ML-DSA anahtariyla JWT yapilandir |
| `AddHybridMigration(options)` | RSA->ML-DSA seffaf goc ekle |
| `AddKeyRotation(options)` | Arka plan servisi olarak otomatik anahtar rotasyonu ekle |
| `MapQuantumJwks(path?)` | Public key kesfi icin JWKS endpoint'i ekle |

---

## Lisans

MIT
