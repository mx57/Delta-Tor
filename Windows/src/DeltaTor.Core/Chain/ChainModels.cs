using System.Text.Json;
using System.Text.Json.Serialization;

namespace DeltaTor.Core.Chain;

public sealed class AmneziaConfig
{
    [JsonPropertyName("private_key")]
    public string PrivateKey { get; set; } = "";

    [JsonPropertyName("address")]
    public string Address { get; set; } = "10.8.0.2/24";

    [JsonPropertyName("dns")]
    public string Dns { get; set; } = "1.1.1.1";

    [JsonPropertyName("peer_public_key")]
    public string PeerPublicKey { get; set; } = "";

    [JsonPropertyName("preshared_key")]
    public string? PresharedKey { get; set; }

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";

    [JsonPropertyName("allowed_ips")]
    public string AllowedIps { get; set; } = "0.0.0.0/0, ::/0";

    [JsonPropertyName("jc")]
    public int Jc { get; set; } = 4;

    [JsonPropertyName("jmin")]
    public int Jmin { get; set; } = 40;

    [JsonPropertyName("jmax")]
    public int Jmax { get; set; } = 70;

    [JsonPropertyName("s1")]
    public int S1 { get; set; } = 20;

    [JsonPropertyName("s2")]
    public int S2 { get; set; } = 30;

    [JsonPropertyName("h1")]
    public uint H1 { get; set; } = 0x12345678;

    [JsonPropertyName("h2")]
    public uint H2 { get; set; } = 0x23456789;

    [JsonPropertyName("h3")]
    public uint H3 { get; set; } = 0x3456789A;

    [JsonPropertyName("h4")]
    public uint H4 { get; set; } = 0x456789AB;

    public bool Validate() =>
        !string.IsNullOrWhiteSpace(PrivateKey) &&
        !string.IsNullOrWhiteSpace(PeerPublicKey) &&
        !string.IsNullOrWhiteSpace(Endpoint);
}

public sealed class WarpProfile
{
    [JsonPropertyName("private_key")]
    public string PrivateKey { get; set; } = "";

    [JsonPropertyName("address_v4")]
    public string AddressV4 { get; set; } = "";

    [JsonPropertyName("address_v6")]
    public string AddressV6 { get; set; } = "";

    [JsonPropertyName("peer_public_key")]
    public string PeerPublicKey { get; set; } = "";

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";

    [JsonPropertyName("reserved")]
    public byte[] Reserved { get; set; } = new byte[3];

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("token")]
    public string? Token { get; set; }

    public bool Validate() =>
        !string.IsNullOrWhiteSpace(PrivateKey) &&
        !string.IsNullOrWhiteSpace(PeerPublicKey) &&
        !string.IsNullOrWhiteSpace(Endpoint);
}

public sealed class MasqueConfig
{
    [JsonPropertyName("server_uri")]
    public string ServerUri { get; set; } = "";

    [JsonPropertyName("verify_tls")]
    public bool VerifyTls { get; set; } = true;

    [JsonPropertyName("use_h2_only")]
    public bool UseH2Only { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string>? Headers { get; set; }

    public bool Validate() =>
        Uri.TryCreate(ServerUri, UriKind.Absolute, out var u) &&
        u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
}

public sealed class Socks5Config
{
    [JsonPropertyName("proxy_addr")]
    public string ProxyAddr { get; set; } = "";

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }
}

public sealed class HopConfig
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = ""; // "direct", "socks5", "awg", "warp", "masque"

    [JsonPropertyName("socks5")]
    public Socks5Config? Socks5 { get; set; }

    [JsonPropertyName("awg")]
    public AmneziaConfig? Awg { get; set; }

    [JsonPropertyName("warp")]
    public WarpProfile? Warp { get; set; }

    [JsonPropertyName("masque")]
    public MasqueConfig? Masque { get; set; }
}

public sealed class ChainProfile
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("hops")]
    public List<HopConfig> Hops { get; set; } = new();

    [JsonPropertyName("bind_port")]
    public int BindPort { get; set; }

    [JsonPropertyName("auth_user")]
    public string? AuthUser { get; set; }

    [JsonPropertyName("auth_pass")]
    public string? AuthPass { get; set; }

    public int CalculateMtu()
    {
        int mtu = 1500;
        foreach (var hop in Hops)
        {
            mtu -= hop.Type.ToLowerInvariant() switch
            {
                "awg" or "warp" => 80,
                "masque" => 96,
                "sstp" => 72,
                _ => 0
            };
        }
        return Math.Max(1280, mtu);
    }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });

    public static ChainProfile? FromJson(string json) =>
        JsonSerializer.Deserialize<ChainProfile>(json);
}

public interface ITransportHop
{
    string Id { get; }
    string DisplayName { get; }
    bool IsRunning { get; }
    ValueTask<bool> StartAsync(CancellationToken cancellationToken = default);
    ValueTask StopAsync();
    TunnelStats? GetStats();
}

public sealed class ChainOrchestrator
{
    private readonly ChainProfile _profile;
    private readonly List<ITransportHop> _hops = new();
    private bool _running;

    public ChainOrchestrator(ChainProfile profile)
    {
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
    }

    public int Mtu => _profile.CalculateMtu();
    public bool IsRunning => _running;

    public async ValueTask<bool> StartAsync(CancellationToken cancellationToken = default)
    {
        if (_profile.Hops.Count == 0 || _profile.Hops.Count > 4)
            return false;

        _running = true;
        return await ValueTask.FromResult(true);
    }

    public async ValueTask StopAsync()
    {
        // Stop hops in reverse order (Exit -> ... -> Entry)
        for (int i = _hops.Count - 1; i >= 0; i--)
        {
            try { await _hops[i].StopAsync(); } catch { }
        }
        _hops.Clear();
        _running = false;
    }
}
