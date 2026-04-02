using System.Security.Cryptography;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemAlgorithmsTests
{
    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void ToMLKemAlgorithm_ValidStrings_ReturnsCorrectAlgorithm(string algName)
    {
        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        Assert.NotNull(algorithm);
    }

    [Theory]
    [InlineData("ml-kem-512")]
    [InlineData("ml-kem-768")]
    [InlineData("ml-kem-1024")]
    public void ToMLKemAlgorithm_CaseInsensitive(string algName)
    {
        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        Assert.NotNull(algorithm);
    }

    [Fact]
    public void ToMLKemAlgorithm_InvalidString_Throws()
    {
        Assert.Throws<ArgumentException>(() => MlKemAlgorithms.ToMLKemAlgorithm("RSA-2048"));
    }

    [Fact]
    public void ToAlgorithmString_AllVariants_ReturnCorrectStrings()
    {
        Assert.Equal("ML-KEM-512", MlKemAlgorithms.ToAlgorithmString(MLKemAlgorithm.MLKem512));
        Assert.Equal("ML-KEM-768", MlKemAlgorithms.ToAlgorithmString(MLKemAlgorithm.MLKem768));
        Assert.Equal("ML-KEM-1024", MlKemAlgorithms.ToAlgorithmString(MLKemAlgorithm.MLKem1024));
    }

    [Fact]
    public void All_ContainsAllThreeAlgorithms()
    {
        Assert.Equal(3, MlKemAlgorithms.All.Count);
        Assert.Contains("ML-KEM-512", MlKemAlgorithms.All);
        Assert.Contains("ML-KEM-768", MlKemAlgorithms.All);
        Assert.Contains("ML-KEM-1024", MlKemAlgorithms.All);
    }
}
