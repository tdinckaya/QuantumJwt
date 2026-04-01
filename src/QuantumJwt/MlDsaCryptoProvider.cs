using Microsoft.IdentityModel.Tokens;

namespace QuantumJwt;

/// <summary>
/// <see cref="ICryptoProvider"/> implementation that creates
/// <see cref="MlDsaSignatureProvider"/> and <see cref="CompositeMlDsaSignatureProvider"/>
/// instances for ML-DSA and Composite ML-DSA algorithms.
/// <para>
/// Automatically registered on <see cref="SecurityKey.CryptoProviderFactory"/>
/// when you create an <see cref="MlDsaSecurityKey"/> or <see cref="CompositeMlDsaSecurityKey"/>.
/// </para>
/// </summary>
public sealed class MlDsaCryptoProvider : ICryptoProvider
{
    /// <summary>
    /// Determines whether this provider supports the given algorithm and key combination.
    /// </summary>
    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
    {
        if (!MlDsaAlgorithms.All.Contains(algorithm))
            return false;

        // Must have a matching key type in args
        foreach (var arg in args)
        {
            if (arg is MlDsaSecurityKey && MlDsaAlgorithms.Pure.Contains(algorithm))
                return true;
            if (arg is CompositeMlDsaSecurityKey && MlDsaAlgorithms.Composite.Contains(algorithm))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Creates a <see cref="SignatureProvider"/> for the given algorithm and key.
    /// </summary>
    public object Create(string algorithm, params object[] args)
    {
        SecurityKey? key = null;
        foreach (var arg in args)
        {
            if (arg is SecurityKey sk)
            {
                key = sk;
                break;
            }
        }

        return key switch
        {
            MlDsaSecurityKey mlDsaKey => new MlDsaSignatureProvider(mlDsaKey, algorithm),
            CompositeMlDsaSecurityKey compositeKey => new CompositeMlDsaSignatureProvider(compositeKey, algorithm),
            _ => throw new NotSupportedException(
                $"Cannot create a signature provider for algorithm '{algorithm}' with key type '{key?.GetType().Name ?? "null"}'.")
        };
    }

    /// <summary>
    /// Releases a cryptographic instance created by this provider.
    /// </summary>
    public void Release(object cryptoInstance)
    {
        if (cryptoInstance is IDisposable disposable)
            disposable.Dispose();
    }
}
