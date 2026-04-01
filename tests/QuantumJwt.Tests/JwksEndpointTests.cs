using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace QuantumJwt.Tests;

public class JwksEndpointTests
{
    [SkippableFact]
    public async Task Endpoint_ReturnsJwkFormat()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa65);

        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddSingleton(key);
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapQuantumJwks();
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/.well-known/jwks.json");

        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("keys", out var keys));
        Assert.Equal(1, keys.GetArrayLength());

        var jwk = keys[0];
        Assert.Equal("ML-DSA", jwk.GetProperty("kty").GetString());
        Assert.Equal("ML-DSA-65", jwk.GetProperty("alg").GetString());
        Assert.Equal(key.KeyId, jwk.GetProperty("kid").GetString());
        Assert.Equal("sig", jwk.GetProperty("use").GetString());
        Assert.True(jwk.TryGetProperty("x", out _)); // public key present
    }

    [SkippableFact]
    public async Task Endpoint_SetsCacheControlHeader()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        using var key = MlDsaSecurityKey.Generate(MLDsaAlgorithm.MLDsa44);

        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddSingleton(key);
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapQuantumJwks();
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/.well-known/jwks.json");

        Assert.True(response.Headers.CacheControl?.Public);
        Assert.Equal(TimeSpan.FromSeconds(3600), response.Headers.CacheControl?.MaxAge);
    }

    [SkippableFact]
    public async Task Endpoint_WithRotationService_IncludesAllActiveKeys()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA not supported on this platform.");

        var rotationOptions = new KeyRotationOptions
        {
            Algorithm = MLDsaAlgorithm.MLDsa44,
            RotationInterval = TimeSpan.FromHours(24),
            KeyOverlapPeriod = TimeSpan.FromHours(1)
        };

        var rotationService = new KeyRotationService(rotationOptions);
        await rotationService.StartAsync(CancellationToken.None);
        await rotationService.RotateKeyAsync(); // Now 2 keys

        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddSingleton(rotationService);
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapQuantumJwks();
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/.well-known/jwks.json");
        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);

        var keys = doc.RootElement.GetProperty("keys");
        Assert.Equal(2, keys.GetArrayLength());

        await rotationService.StopAsync(CancellationToken.None);
        rotationService.Dispose();
    }
}
