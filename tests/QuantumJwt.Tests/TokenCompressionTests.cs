using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumJwt.Tests;

public class TokenCompressionTests
{
    private static string CreateTestJwt(int extraClaimCount = 0)
    {
        // Create a simple RSA-signed JWT for testing (doesn't need ML-DSA)
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa);
        var handler = new JwtSecurityTokenHandler();

        var claims = new List<Claim>
        {
            new("sub", "user1"),
            new("role", "admin")
        };

        for (var i = 0; i < extraClaimCount; i++)
        {
            claims.Add(new Claim($"custom-{i}", $"value-{i}-{new string('x', 50)}"));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            Issuer = "test",
            Audience = "test"
        };

        return handler.CreateEncodedJwt(descriptor);
    }

    [Fact]
    public void AnalyzeTokenSize_ReturnsCorrectBreakdown()
    {
        var jwt = CreateTestJwt();
        var report = TokenCompression.AnalyzeTokenSize(jwt);

        var parts = jwt.Split('.');
        Assert.True(report.TotalBytes > 0);
        Assert.True(report.HeaderBytes > 0);
        Assert.True(report.PayloadBytes > 0);
        Assert.True(report.SignatureBytes > 0);
        Assert.Equal(report.TotalBytes + 7, report.AuthorizationHeaderBytes);
        Assert.Equal(report.HeaderBytes + report.PayloadBytes + report.SignatureBytes + 2, report.TotalBytes); // +2 for dots
    }

    [Fact]
    public void AnalyzeTokenSize_SmallToken_NoWarning()
    {
        var jwt = CreateTestJwt();
        var report = TokenCompression.AnalyzeTokenSize(jwt);

        // A simple RSA JWT should be well under 4KB
        Assert.True(report.TotalBytes < 4096);
        Assert.Equal("Token size is within safe limits.", report.Warning);
    }

    [Fact]
    public void AnalyzeTokenSize_LargeToken_WarnsAboutNginx()
    {
        // Create a token with many claims to exceed 4KB
        var jwt = CreateTestJwt(extraClaimCount: 50);
        var report = TokenCompression.AnalyzeTokenSize(jwt);

        if (report.AuthorizationHeaderBytes > 4096)
        {
            Assert.Contains("Nginx", report.Warning);
            Assert.Contains("large_client_header_buffers", report.Recommendation);
        }
    }

    [Fact]
    public void CompressAndDecompress_RoundTrip()
    {
        var original = CreateTestJwt(extraClaimCount: 10);

        var compressed = TokenCompression.CompressToken(original);
        var decompressed = TokenCompression.DecompressToken(compressed);

        // The payload should be identical after round-trip
        var originalParts = original.Split('.');
        var decompressedParts = decompressed.Split('.');

        Assert.Equal(originalParts[1], decompressedParts[1]); // payload matches
    }

    [Fact]
    public void CompressToken_AddsZipHeader()
    {
        var jwt = CreateTestJwt();
        var compressed = TokenCompression.CompressToken(jwt);

        var headerPart = compressed.Split('.')[0];
        var headerJson = Base64UrlEncoder.Decode(headerPart);

        Assert.Contains("\"zip\":\"DEF\"", headerJson);
    }

    [Fact]
    public void DecompressToken_UncompressedToken_ReturnsSameToken()
    {
        var jwt = CreateTestJwt();
        var result = TokenCompression.DecompressToken(jwt);

        Assert.Equal(jwt, result);
    }

    [Fact]
    public void AnalyzeTokenSize_InvalidJwt_ThrowsArgException()
    {
        Assert.Throws<ArgumentException>(() => TokenCompression.AnalyzeTokenSize("not-a-jwt"));
    }

    [Fact]
    public void TokenSizeReport_ToString_ContainsAllInfo()
    {
        var jwt = CreateTestJwt();
        var report = TokenCompression.AnalyzeTokenSize(jwt);

        var str = report.ToString();
        Assert.Contains("bytes", str);
        Assert.Contains("header:", str);
        Assert.Contains("payload:", str);
        Assert.Contains("sig:", str);
    }
}
