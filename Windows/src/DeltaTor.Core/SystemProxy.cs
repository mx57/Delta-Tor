using System.Runtime.InteropServices;
using System.Text.Json;
using DeltaTor.Core.Util;
using Microsoft.Win32;

namespace DeltaTor.Core;

/// <summary>
/// Points WinINET (the per-user Windows proxy Edge/Chrome/IE read) at the
/// winning Tor instance's own HTTPTunnelPort (an HTTP CONNECT front Tor
/// opens next to its SOCKS5 port). Applied only in System proxy mode after
/// bootstrap reaches 100% with the "No VPN and System Proxy" toggle off;
/// the values that were there before are saved once and restored when the
/// proxy is cleared (disconnect, teardown, mode change to Tun, app exit).
/// </summary>
public static class SystemProxy
{
    private const string KeyPath =
        @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    private static readonly object Lock = new();
    private static bool _applied;
    private static ProxyBackup? _prevBackup;

    private sealed record ProxyBackup(
        bool ProxyEnable,
        string ProxyServer,
        string? ProxyOverride,
        string? AutoConfigURL
    );

    private static string BackupFilePath
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DeltaTor");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "system-proxy-backup.json");
        }
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(
        IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    /// <summary>True while this app owns the machine proxy (must be cleared later).</summary>
    public static bool IsApplied
    {
        get { lock (Lock) return _applied; }
    }

    /// <summary>Restores pre-crash system proxy settings if backup file exists from abnormal termination.</summary>
    public static void RestoreIfCrashed()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(BackupFilePath))
                {
                    AppLog.I("SystemProxy", "Lingering system-proxy-backup.json detected from previous crash; restoring...");
                    Clear();
                }
            }
            catch (Exception e)
            {
                AppLog.W("SystemProxy", $"Error during crash proxy restore check: {e.Message}");
            }
        }
    }

    /// <summary>Enable the machine proxy at host:port (HTTP-proxy form).
    /// <paramref name="port"/> is the winner's Tor HTTPTunnelPort. No-op-safe
    /// on failure.</summary>
    public static void Apply(string host, int port)
    {
        lock (Lock)
        {
            if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535)
            {
                AppLog.W("SystemProxy", $"Invalid host or port: {host}:{port}; system proxy not set");
                return;
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
                if (key == null)
                {
                    AppLog.W("SystemProxy", "Internet Settings key missing; system proxy not set");
                    return;
                }

                if (!_applied)
                {
                    var currentEnable = key.GetValue("ProxyEnable") is int pe && pe != 0;
                    var currentServer = key.GetValue("ProxyServer") as string ?? "";
                    var currentOverride = key.GetValue("ProxyOverride") as string;
                    var currentAutoConfig = key.GetValue("AutoConfigURL") as string;

                    var backup = new ProxyBackup(currentEnable, currentServer, currentOverride, currentAutoConfig);
                    _prevBackup = backup;

                    // Persist backup to disk before touching registry
                    try
                    {
                        var json = JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true });
                        File.WriteAllText(BackupFilePath, json);
                    }
                    catch (Exception ex)
                    {
                        AppLog.W("SystemProxy", $"Failed to save proxy backup file: {ex.Message}");
                    }
                }

                var target = $"{host}:{port}";
                key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                key.SetValue("ProxyServer", target, RegistryValueKind.String);
                key.Flush();

                if (!NotifyWinInet())
                {
                    AppLog.W("SystemProxy", "InternetSetOption failed to broadcast settings change");
                }

                _applied = true;
                AppLog.I("SystemProxy", $"System proxy set to {target} (Tor HTTPTunnelPort)");
            }
            catch (Exception e)
            {
                AppLog.W("SystemProxy", $"Failed to set system proxy: {e.Message}");
            }
        }
    }

    /// <summary>Put the pre-app values back. No-op when nothing was applied.</summary>
    public static void Clear()
    {
        lock (Lock)
        {
            if (!_applied && !File.Exists(BackupFilePath)) return;

            try
            {
                var backup = _prevBackup;
                if (backup == null && File.Exists(BackupFilePath))
                {
                    try
                    {
                        var text = File.ReadAllText(BackupFilePath);
                        backup = JsonSerializer.Deserialize<ProxyBackup>(text);
                    }
                    catch (Exception ex)
                    {
                        AppLog.W("SystemProxy", $"Failed to read proxy backup file: {ex.Message}");
                    }
                }

                using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
                if (key != null && backup != null)
                {
                    key.SetValue("ProxyEnable", backup.ProxyEnable ? 1 : 0, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", backup.ProxyServer, RegistryValueKind.String);
                    if (!string.IsNullOrEmpty(backup.ProxyOverride))
                        key.SetValue("ProxyOverride", backup.ProxyOverride, RegistryValueKind.String);
                    else
                        key.DeleteValue("ProxyOverride", false);

                    if (!string.IsNullOrEmpty(backup.AutoConfigURL))
                        key.SetValue("AutoConfigURL", backup.AutoConfigURL, RegistryValueKind.String);
                    else
                        key.DeleteValue("AutoConfigURL", false);

                    key.Flush();
                }

                if (!NotifyWinInet())
                {
                    AppLog.W("SystemProxy", "InternetSetOption failed to broadcast restore change");
                }

                // Delete backup file only after registry write succeeds
                try
                {
                    if (File.Exists(BackupFilePath)) File.Delete(BackupFilePath);
                }
                catch { /* ignored */ }

                _applied = false;
                _prevBackup = null;
                AppLog.I("SystemProxy", "System proxy restored to the previous value");
            }
            catch (Exception e)
            {
                AppLog.W("SystemProxy", $"Failed to restore system proxy: {e.Message}");
            }
        }
    }

    /// <summary>Broadcast the registry change to running apps (WinINET).</summary>
    private static bool NotifyWinInet()
    {
        var r1 = InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        var r2 = InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        return r1 && r2;
    }
}
