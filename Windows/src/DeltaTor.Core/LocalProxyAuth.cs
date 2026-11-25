using System.IO;
using System.Security.Cryptography;
using System.Text;
using DeltaTor.Core.Util;

namespace DeltaTor.Core;

/// <summary>
/// Shared SOCKS5 local proxy authentication handler.
///
/// Implements RFC 1929 Username/Password Authentication for the local SOCKS5
/// listener side. When auth is enabled, clients must provide valid credentials
/// before the proxy will accept CONNECT or FWD_UDP requests. This prevents
/// other apps on the machine from abusing the local proxy.
/// </summary>
public static class LocalProxyAuth
{
    private const string TAG = "LocalProxyAuth";

    /// <summary>
    /// Generates random one-time session credentials via CSPRNG.
    /// </summary>
    public static (string Username, string Password) GenerateSessionCredentials()
    {
        var userBytes = new byte[16];
        var passBytes = new byte[16];
        RandomNumberGenerator.Fill(userBytes);
        RandomNumberGenerator.Fill(passBytes);
        return (Convert.ToHexString(userBytes).ToLowerInvariant(), Convert.ToHexString(passBytes).ToLowerInvariant());
    }

    /// <summary>
    /// Handle SOCKS5 greeting authentication after VER, NMETHODS and METHODS
    /// have been read from the client. Returns true when authentication
    /// succeeded (or was explicitly allowed without auth), false when rejected.
    /// </summary>
    public static bool HandleGreeting(
        byte[] methods,
        Stream input,
        Stream output,
        string? username,
        string? password,
        bool allowNoAuth = false)
    {
        var hasCredentials = !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password);

        if (!hasCredentials)
        {
            if (allowNoAuth && Array.IndexOf(methods, (byte)0x00) >= 0)
            {
                // Explicitly allowed no authentication required (e.g. System Proxy mode).
                output.Write(new byte[] { 0x05, 0x00 });
                output.Flush();
                return true;
            }
            AppLog.W(TAG, "Rejecting client: credentials required but not configured (NO AUTH disabled)");
            output.Write(new byte[] { 0x05, 0xFF });
            output.Flush();
            return false;
        }

        // Check if client supports USERNAME/PASSWORD (0x02).
        if (Array.IndexOf(methods, (byte)0x02) < 0)
        {
            // Client doesn't support USERNAME/PASSWORD — reject with 0xFF (no
            // acceptable methods). Expected for readiness probes and apps that
            // only offer NO_AUTH.
            AppLog.D(TAG, "Client does not support USERNAME/PASSWORD auth, rejecting");
            output.Write(new byte[] { 0x05, 0xFF });
            output.Flush();
            return false;
        }

        // Select USERNAME/PASSWORD auth method.
        output.Write(new byte[] { 0x05, 0x02 });
        output.Flush();

        // RFC 1929 subnegotiation.
        var authVer = input.ReadByte();
        if (authVer != 0x01)
        {
            AppLog.W(TAG, $"Invalid auth subnegotiation version: {authVer}");
            output.Write(new byte[] { 0x01, 0x01 }); // failure
            output.Flush();
            return false;
        }

        var uLen = input.ReadByte();
        if (uLen < 0) return false;
        var uBytes = new byte[uLen];
        ReadExactly(input, uBytes);

        var pLen = input.ReadByte();
        if (pLen < 0) return false;
        var pBytes = new byte[pLen];
        ReadExactly(input, pBytes);

        var expectedUser = Encoding.UTF8.GetBytes(username!);
        var expectedPass = Encoding.UTF8.GetBytes(password!);

        var userOk = CryptographicOperations.FixedTimeEquals(uBytes, expectedUser);
        var passOk = CryptographicOperations.FixedTimeEquals(pBytes, expectedPass);

        if (userOk && passOk)
        {
            // Auth success.
            output.Write(new byte[] { 0x01, 0x00 });
            output.Flush();
            return true;
        }

        // Auth failure.
        AppLog.W(TAG, "Authentication failed for local proxy client");
        output.Write(new byte[] { 0x01, 0x01 });
        output.Flush();
        return false;
    }

    private static void ReadExactly(Stream input, byte[] buf)
    {
        var off = 0;
        while (off < buf.Length)
        {
            var n = input.Read(buf, off, buf.Length - off);
            if (n <= 0) throw new IOException("Unexpected end of stream during auth");
            off += n;
        }
    }
}
