using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text.Json;
using DeltaTor.Core.Util;

namespace DeltaTor.Core;

/// <summary>
/// Checks GitHub for a newer DeltaTor release, raises an in-app banner (via
/// <see cref="AppState.ReleaseState"/>) and a tray/toast notification whenever
/// one exists, and opens the release page in a browser.
///
/// The notification is repeated on every launch while a newer release exists;
/// there is no dismiss state (Windows counterpart of Android ReleaseChecker).
/// </summary>
public static class ReleaseChecker
{
    private const string TAG = "ReleaseChecker";
    private const string Repo = "mx57/Delta-Tor";
    private const string ApiLatest = "https://api.github.com/repos/" + Repo + "/releases/latest";
    private const string GithubUrl = "https://github.com/" + Repo;
    private const int TimeoutMs = 8_000;

    /// <summary>The platform notification surface (Android: system notification id 42, channel updates).</summary>
    public sealed record ReleaseNotice(string Title, string Body, string Url);

    /// <summary>Raised whenever a newer release is found, once per check. UI (stage 3) turns it into a toast/tray notification.</summary>
    public static event Action<ReleaseNotice>? NotificationRaised;

    public static void OpenInBrowser(string url)
    {
        try
        {
            var targetUrl = (string.IsNullOrWhiteSpace(url) || !url.StartsWith($"https://github.com/{Repo}", StringComparison.OrdinalIgnoreCase))
                ? GithubUrl
                : url;

            Process.Start(new ProcessStartInfo(targetUrl) { UseShellExecute = true });
        }
        catch (Exception e)
        {
            AppLog.W(TAG, $"Could not open browser: {e.Message}");
        }
    }

    public static bool Check() => Check(null);

    public static bool Check(string? socksProxy)
    {
        return CheckAsync(socksProxy).GetAwaiter().GetResult();
    }

    public static Task<bool> CheckAsync() => CheckAsync(null);

    public static async Task<bool> CheckAsync(string? socksProxy)
    {
        try
        {
            using var client = CreateClient(socksProxy);
            using var resp = await client.GetAsync(ApiLatest).ConfigureAwait(false);
            if ((int)resp.StatusCode != 200)
            {
                AppLog.W(TAG, $"Update check HTTP {(int)resp.StatusCode}");
                AppState.UpdateRelease(r => r with { Checking = false });
                return false;
            }

            var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            string tag;
            string htmlUrl;
            using (var doc = JsonDocument.Parse(body))
            {
                tag = doc.RootElement.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
                htmlUrl = doc.RootElement.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : "";
            }
            tag = tag.Trim();
            if (tag.StartsWith("v", StringComparison.Ordinal)) tag = tag[1..];
            if (string.IsNullOrWhiteSpace(htmlUrl) || !htmlUrl.StartsWith($"https://github.com/{Repo}/releases/", StringComparison.OrdinalIgnoreCase))
            {
                htmlUrl = $"{GithubUrl}/releases/tag/{tag}";
            }

            var current = CurrentVersion();
            var newer = tag.Length > 0 && CompareVersions(current, tag) < 0;
            AppLog.I(TAG, $"Latest release: {tag} (current {current}, newer={newer})");

            AppState.UpdateRelease(r => r with
            {
                Checking = false,
                LatestVersion = tag,
                LatestUrl = htmlUrl,
                Newer = newer
            });
            if (newer)
            {
                NotificationRaised?.Invoke(new ReleaseNotice(
                    $"DeltaTor {tag} available",
                    "A new release is out \u2014 tap to open it on GitHub.",
                    htmlUrl));
            }
            return true;
        }
        catch (Exception e)
        {
            AppLog.W(TAG, $"Update check failed: {e.Message}");
            AppState.UpdateRelease(r => r with { Checking = false });
            return false;
        }
    }

    /// <summary>
    /// The version this build reports: the entry assembly's version (the
    /// release workflow stamps it from the tag, the csproj fallback is 2.0.0),
    /// trimmed to three parts the way versionName / compareVersions see it.
    /// </summary>
    private static string CurrentVersion()
    {
        var v = Assembly.GetEntryAssembly()?.GetName().Version
            ?? typeof(ReleaseChecker).Assembly.GetName().Version;
        if (v == null) return "2.0.0";
        var build = v.Build < 0 ? 0 : v.Build;
        return $"{v.Major}.{v.Minor}.{build}";
    }

    /// <summary>
    /// Numeric segment compare, identical to Android's compareVersions:
    /// non-numeric segments are dropped, missing segments count as 0.
    /// Returns negative when a is older than b.
    /// </summary>
    public static int CompareVersions(string a, string b)
    {
        var pa = IntParts(a);
        var pb = IntParts(b);
        var count = Math.Max(pa.Count, pb.Count);
        for (var i = 0; i < count; i++)
        {
            var x = i < pa.Count ? pa[i] : 0;
            var y = i < pb.Count ? pb[i] : 0;
            if (x != y) return x - y;
        }
        return 0;
    }

    private static List<int> IntParts(string s)
    {
        var parts = new List<int>();
        foreach (var p in s.Split('.'))
            if (int.TryParse(p, out var v)) parts.Add(v);
        return parts;
    }

    private static HttpClient CreateClient(string? socksProxy = null)
    {
        var handler = new SocketsHttpHandler();
        var proxyAddr = socksProxy;
        if (string.IsNullOrEmpty(proxyAddr) && AppState.State.TorRunning)
        {
            proxyAddr = $"socks5://127.0.0.1:{Config.ProxyPort}";
        }
        if (!string.IsNullOrEmpty(proxyAddr))
        {
            handler.Proxy = new WebProxy(proxyAddr);
            handler.UseProxy = true;
        }
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("DeltaTor-Windows");
        return c;
    }
}
