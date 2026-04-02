using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace QuantumDataProtection;

/// <summary>
/// Extension methods for integrating ML-KEM key wrapping into ASP.NET Core Data Protection.
/// </summary>
public static class MlKemDataProtectionExtensions
{
    /// <summary>
    /// Configures Data Protection to encrypt XML keys using ML-KEM (FIPS 203)
    /// key encapsulation + AES-256-GCM.
    /// <para>
    /// This replaces the default RSA key wrapping with post-quantum key encapsulation,
    /// protecting cookies, sessions, and anti-forgery tokens against
    /// "harvest now, decrypt later" attacks.
    /// </para>
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddDataProtection()
    ///     .ProtectKeysWithMlKem(options =>
    ///     {
    ///         options.Algorithm = MLKemAlgorithm.MLKem768;
    ///         options.KeyStoreDirectory = "/var/keys";
    ///         options.KeyStorePassword = config["KeyPassword"];
    ///     });
    /// </code>
    /// </example>
    public static IDataProtectionBuilder ProtectKeysWithMlKem(
        this IDataProtectionBuilder builder,
        Action<MlKemDataProtectionOptions> configure)
    {
        var options = new MlKemDataProtectionOptions();
        configure(options);

        // Register options as singleton for both encryptor and decryptor
        builder.Services.AddSingleton(options);

        // Register encryptor and decryptor
        builder.Services.AddSingleton<IXmlEncryptor>(sp => new MlKemXmlEncryptor(options));
        builder.Services.AddSingleton<IXmlDecryptor, MlKemXmlDecryptor>();

        return builder;
    }
}
