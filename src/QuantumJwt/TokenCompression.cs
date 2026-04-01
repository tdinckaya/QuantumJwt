using System.IO.Compression;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// Utilities for analyzing and compressing post-quantum JWT tokens.
/// <para>
/// ML-DSA signatures are 10-20x larger than RSA, which can exceed HTTP header
/// limits on some infrastructure (Nginx default: 4KB, Apache: 8KB).
/// This class provides tools to diagnose and mitigate token size issues.
/// </para>
/// </summary>
public static class TokenCompression
{
    /// <summary>
    /// Analyzes a JWT token's size and returns infrastructure compatibility warnings.
    /// </summary>
    /// <param name="jwt">The JWT token string (header.payload.signature).</param>
    /// <returns>A <see cref="TokenSizeReport"/> with size breakdown and recommendations.</returns>
    public static TokenSizeReport AnalyzeTokenSize(string jwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwt);

        var parts = jwt.Split('.');
        if (parts.Length < 3)
            throw new ArgumentException("Invalid JWT format. Expected header.payload.signature.", nameof(jwt));

        var totalBytes = Encoding.UTF8.GetByteCount(jwt);
        var headerBytes = Encoding.UTF8.GetByteCount(parts[0]);
        var payloadBytes = Encoding.UTF8.GetByteCount(parts[1]);
        var signatureBytes = Encoding.UTF8.GetByteCount(parts[2]);

        // "Bearer " prefix (7 bytes) + token in Authorization header
        var authHeaderBytes = totalBytes + 7;

        var warnings = new List<string>();
        var recommendations = new List<string>();

        if (authHeaderBytes > 4096)
        {
            warnings.Add("Exceeds Nginx default header limit (4KB).");
            recommendations.Add("Nginx: large_client_header_buffers 4 16k;");
        }

        if (authHeaderBytes > 8192)
        {
            warnings.Add("Exceeds Apache default header limit (8KB).");
            recommendations.Add("Apache: LimitRequestFieldSize 16384");
        }

        if (authHeaderBytes > 16384)
        {
            warnings.Add("Exceeds AWS ALB / Cloudflare header limit (16KB).");
            recommendations.Add("Consider storing the token in the request body or using a token reference pattern.");
        }

        if (totalBytes > 4096)
        {
            recommendations.Add("Kestrel: options.Limits.MaxRequestHeadersTotalSize = 32768;");
        }

        if (payloadBytes > signatureBytes)
        {
            recommendations.Add("Payload is larger than signature — reduce claims to minimize token size.");
        }

        return new TokenSizeReport
        {
            TotalBytes = totalBytes,
            HeaderBytes = headerBytes,
            PayloadBytes = payloadBytes,
            SignatureBytes = signatureBytes,
            AuthorizationHeaderBytes = authHeaderBytes,
            Warning = warnings.Count > 0 ? string.Join(" ", warnings) : "Token size is within safe limits.",
            Recommendation = recommendations.Count > 0
                ? string.Join(" | ", recommendations)
                : "No action needed."
        };
    }

    /// <summary>
    /// Compresses a JWT token's payload using DEFLATE.
    /// The compressed token uses a custom <c>zip</c> header claim to indicate compression.
    /// <para>
    /// <b>Note:</b> The receiving party must use <see cref="DecompressToken"/> to restore
    /// the original token before standard JWT validation.
    /// </para>
    /// </summary>
    /// <param name="jwt">The original JWT token string.</param>
    /// <returns>A JWT with compressed payload (may be smaller or larger depending on claim content).</returns>
    public static string CompressToken(string jwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwt);

        var parts = jwt.Split('.');
        if (parts.Length < 3)
            throw new ArgumentException("Invalid JWT format.", nameof(jwt));

        // Decode payload
        var payloadJson = Base64UrlEncoder.Decode(parts[1]);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

        // Compress with DEFLATE
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            deflate.Write(payloadBytes, 0, payloadBytes.Length);
        }

        var compressedPayload = Base64UrlEncoder.Encode(output.ToArray());

        // Decode header, add "zip":"DEF" claim
        var headerJson = Base64UrlEncoder.Decode(parts[0]);
        if (!headerJson.Contains("\"zip\""))
        {
            // Insert zip claim before the closing brace
            headerJson = headerJson.TrimEnd('}') + ",\"zip\":\"DEF\"}";
        }

        var compressedHeader = Base64UrlEncoder.Encode(headerJson);

        // Signature remains unchanged (it signed the original header.payload)
        // NOTE: This means the compressed token cannot be validated directly.
        // It must be decompressed first, then validated.
        return $"{compressedHeader}.{compressedPayload}.{parts[2]}";
    }

    /// <summary>
    /// Decompresses a JWT token that was compressed with <see cref="CompressToken"/>.
    /// </summary>
    /// <param name="compressedJwt">The compressed JWT token.</param>
    /// <returns>The original JWT token with decompressed payload.</returns>
    public static string DecompressToken(string compressedJwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compressedJwt);

        var parts = compressedJwt.Split('.');
        if (parts.Length < 3)
            throw new ArgumentException("Invalid JWT format.", nameof(compressedJwt));

        // Check if the header contains "zip":"DEF"
        var headerJson = Base64UrlEncoder.Decode(parts[0]);
        if (!headerJson.Contains("\"zip\":\"DEF\""))
        {
            // Not compressed, return as-is
            return compressedJwt;
        }

        // Decompress payload
        var compressedBytes = Base64UrlEncoder.DecodeBytes(parts[1]);
        using var input = new MemoryStream(compressedBytes);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);

        var payloadJson = Encoding.UTF8.GetString(output.ToArray());
        var decompressedPayload = Base64UrlEncoder.Encode(payloadJson);

        // Remove "zip":"DEF" from header
        headerJson = headerJson.Replace(",\"zip\":\"DEF\"", "").Replace("\"zip\":\"DEF\",", "");
        var originalHeader = Base64UrlEncoder.Encode(headerJson);

        return $"{originalHeader}.{decompressedPayload}.{parts[2]}";
    }
}

/// <summary>
/// Size analysis report for a JWT token with infrastructure compatibility warnings.
/// </summary>
public sealed class TokenSizeReport
{
    /// <summary>Total token size in bytes.</summary>
    public required int TotalBytes { get; init; }

    /// <summary>JWT header (first segment) size in bytes.</summary>
    public required int HeaderBytes { get; init; }

    /// <summary>JWT payload (second segment) size in bytes.</summary>
    public required int PayloadBytes { get; init; }

    /// <summary>JWT signature (third segment) size in bytes.</summary>
    public required int SignatureBytes { get; init; }

    /// <summary>
    /// Size of the full Authorization header (<c>"Bearer " + token</c>) in bytes.
    /// This is what matters for HTTP header limit checks.
    /// </summary>
    public required int AuthorizationHeaderBytes { get; init; }

    /// <summary>
    /// Infrastructure compatibility warnings (e.g. "Exceeds Nginx default header limit").
    /// </summary>
    public required string Warning { get; init; }

    /// <summary>
    /// Actionable recommendations to resolve size issues.
    /// </summary>
    public required string Recommendation { get; init; }

    /// <inheritdoc />
    public override string ToString() =>
        $"Token: {TotalBytes} bytes (header:{HeaderBytes} payload:{PayloadBytes} sig:{SignatureBytes}) " +
        $"| Auth header: {AuthorizationHeaderBytes} bytes | {Warning}";
}
