using System.Text.Json;
using DeltaTor.Core.Chain;
using Xunit;

namespace DeltaTor.Core.Tests;

public class ChainProfileTests
{
    [Fact]
    public void MtuCalculation_Default_Is1500()
    {
        var profile = new ChainProfile { Name = "Empty" };
        Assert.Equal(1500, profile.CalculateMtu());
    }

    [Fact]
    public void MtuCalculation_WithAwgAndMasque_ReducesCorrectly()
    {
        var profile = new ChainProfile
        {
            Name = "Amnezia -> Masque",
            Hops = new List<HopConfig>
            {
                new() { Type = "awg" },
                new() { Type = "masque" }
            }
        };

        // 1500 - 80 (awg) - 96 (masque) = 1324
        Assert.Equal(1324, profile.CalculateMtu());
    }

    [Fact]
    public void MtuCalculation_FloorsAt1280()
    {
        var profile = new ChainProfile
        {
            Name = "Heavy chain",
            Hops = new List<HopConfig>
            {
                new() { Type = "awg" },
                new() { Type = "warp" },
                new() { Type = "masque" },
                new() { Type = "sstp" }
            }
        };

        // 1500 - 80 - 80 - 96 - 72 = 1172 -> floored at 1280
        Assert.Equal(1280, profile.CalculateMtu());
    }

    [Fact]
    public void SerializationRoundtrip_PreservesData()
    {
        var profile = new ChainProfile
        {
            Id = "test-chain-1",
            Name = "Tor -> WARP",
            BindPort = 19050,
            AuthUser = "user1",
            AuthPass = "pass1",
            Hops = new List<HopConfig>
            {
                new()
                {
                    Type = "socks5",
                    Socks5 = new Socks5Config { ProxyAddr = "127.0.0.1:9050" }
                },
                new()
                {
                    Type = "warp",
                    Warp = new WarpProfile
                    {
                        PrivateKey = "privkey",
                        PeerPublicKey = "pubkey",
                        Endpoint = "162.159.192.1:2408",
                        Reserved = new byte[] { 1, 2, 3 }
                    }
                }
            }
        };

        var json = profile.ToJson();
        var roundtripped = ChainProfile.FromJson(json);

        Assert.NotNull(roundtripped);
        Assert.Equal("test-chain-1", roundtripped.Id);
        Assert.Equal("Tor -> WARP", roundtripped.Name);
        Assert.Equal(19050, roundtripped.BindPort);
        Assert.Equal("user1", roundtripped.AuthUser);
        Assert.Equal(2, roundtripped.Hops.Count);
        Assert.Equal("socks5", roundtripped.Hops[0].Type);
        Assert.Equal("warp", roundtripped.Hops[1].Type);
        Assert.Equal(new byte[] { 1, 2, 3 }, roundtripped.Hops[1].Warp!.Reserved);
    }

    [Fact]
    public void AmneziaConfig_Validate_RequiresKeysAndEndpoint()
    {
        var valid = new AmneziaConfig
        {
            PrivateKey = "aGVsbG8=",
            PeerPublicKey = "d29ybGQ=",
            Endpoint = "192.0.2.1:51820"
        };
        Assert.True(valid.Validate());

        var invalid = new AmneziaConfig
        {
            PrivateKey = "",
            PeerPublicKey = "d29ybGQ=",
            Endpoint = "192.0.2.1:51820"
        };
        Assert.False(invalid.Validate());
    }

    [Fact]
    public void MasqueConfig_Validate_RequiresHttpsUri()
    {
        var valid = new MasqueConfig { ServerUri = "https://masque.example.com:4433" };
        Assert.True(valid.Validate());

        var invalidHttp = new MasqueConfig { ServerUri = "http://masque.example.com" };
        Assert.False(invalidHttp.Validate());

        var invalidMalformed = new MasqueConfig { ServerUri = "not-a-valid-uri" };
        Assert.False(invalidMalformed.Validate());
    }
}
