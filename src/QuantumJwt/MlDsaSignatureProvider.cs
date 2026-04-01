using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// <see cref="SignatureProvider"/> implementation that delegates to
/// .NET 10's <see cref="MLDsa"/> for signing and verification.
/// </summary>
public sealed class MlDsaSignatureProvider : SignatureProvider
{
    private readonly MlDsaSecurityKey _key;

    /// <summary>
    /// Initializes a new <see cref="MlDsaSignatureProvider"/>.
    /// </summary>
    /// <param name="key">The ML-DSA security key.</param>
    /// <param name="algorithm">
    /// The JWT algorithm identifier (e.g. <see cref="MlDsaAlgorithms.MlDsa65"/>).
    /// </param>
    public MlDsaSignatureProvider(MlDsaSecurityKey key, string algorithm)
        : base(key, algorithm)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));

        // Verify algorithm matches the key
        var expectedAlg = MlDsaAlgorithms.ToJwtAlgorithm(key.Algorithm);
        if (!string.Equals(expectedAlg, algorithm, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Algorithm mismatch: key is {expectedAlg} but '{algorithm}' was requested.",
                nameof(algorithm));
    }

    /// <summary>
    /// Signs the input data using ML-DSA.
    /// </summary>
    /// <param name="input">The data to sign.</param>
    /// <returns>The ML-DSA signature.</returns>
    /// <exception cref="InvalidOperationException">The key does not contain a private key.</exception>
    public override byte[] Sign(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (_key.PrivateKeyStatus != PrivateKeyStatus.Exists)
            throw new InvalidOperationException(
                "Cannot sign: the key does not contain a private key.");

        return _key.MlDsa.SignData(input, context: null);
    }

    /// <summary>
    /// Verifies an ML-DSA signature against the input data.
    /// </summary>
    /// <param name="input">The original data.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><c>true</c> if the signature is valid; otherwise <c>false</c>.</returns>
    public override bool Verify(byte[] input, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(signature);

        return _key.MlDsa.VerifyData(input, signature, context: null);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        // Do not dispose the key — ownership belongs to MlDsaSecurityKey
    }
}
