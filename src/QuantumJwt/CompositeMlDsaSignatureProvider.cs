using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// <see cref="SignatureProvider"/> implementation that delegates to
/// .NET 10's <see cref="CompositeMLDsa"/> for hybrid post-quantum signing and verification.
/// </summary>
public sealed class CompositeMlDsaSignatureProvider : SignatureProvider
{
    private readonly CompositeMlDsaSecurityKey _key;

    /// <summary>
    /// Initializes a new <see cref="CompositeMlDsaSignatureProvider"/>.
    /// </summary>
    /// <param name="key">The composite ML-DSA security key.</param>
    /// <param name="algorithm">
    /// The JWT algorithm identifier (e.g. <see cref="MlDsaAlgorithms.MlDsa65WithRSA4096Pss"/>).
    /// </param>
    public CompositeMlDsaSignatureProvider(CompositeMlDsaSecurityKey key, string algorithm)
        : base(key, algorithm)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));

        var expectedAlg = MlDsaAlgorithms.ToJwtAlgorithm(key.Algorithm);
        if (!string.Equals(expectedAlg, algorithm, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Algorithm mismatch: key is {expectedAlg} but '{algorithm}' was requested.",
                nameof(algorithm));
    }

    /// <summary>
    /// Signs the input data using composite ML-DSA (classical + quantum signature).
    /// </summary>
    /// <exception cref="InvalidOperationException">The key does not contain a private key.</exception>
    public override byte[] Sign(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (_key.PrivateKeyStatus != PrivateKeyStatus.Exists)
            throw new InvalidOperationException(
                "Cannot sign: the key does not contain a private key.");

        return _key.CompositeKey.SignData(input, context: null);
    }

    /// <summary>
    /// Verifies a composite ML-DSA signature against the input data.
    /// Both the classical and quantum signatures must be valid.
    /// </summary>
    public override bool Verify(byte[] input, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(signature);

        return _key.CompositeKey.VerifyData(input, signature, context: null);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        // Do not dispose the key — ownership belongs to CompositeMlDsaSecurityKey
    }
}
