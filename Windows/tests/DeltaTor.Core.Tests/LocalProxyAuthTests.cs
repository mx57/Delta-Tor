using System.IO;
using System.Text;
using DeltaTor.Core;
using Xunit;

namespace DeltaTor.Core.Tests;

public class LocalProxyAuthTests
{
    [Fact]
    public void GenerateSessionCredentials_ReturnsValidHexStrings()
    {
        var (user, pass) = LocalProxyAuth.GenerateSessionCredentials();

        Assert.Equal(32, user.Length); // 16 bytes = 32 hex chars
        Assert.Equal(32, pass.Length);
        Assert.Matches("^[0-9a-f]+$", user);
        Assert.Matches("^[0-9a-f]+$", pass);
    }

    [Fact]
    public void HandleGreeting_AllowNoAuth_WhenCredentialsNull_Succeeds()
    {
        using var input = new MemoryStream();
        using var output = new MemoryStream();
        var methods = new byte[] { 0x00 }; // NO_AUTH

        var ok = LocalProxyAuth.HandleGreeting(
            methods, input, output, username: null, password: null, allowNoAuth: true
        );

        Assert.True(ok);
        Assert.Equal(new byte[] { 0x05, 0x00 }, output.ToArray());
    }

    [Fact]
    public void HandleGreeting_CredentialsRequired_ClientOffersOnlyNoAuth_Rejects()
    {
        using var input = new MemoryStream();
        using var output = new MemoryStream();
        var methods = new byte[] { 0x00 }; // NO_AUTH only

        var ok = LocalProxyAuth.HandleGreeting(
            methods, input, output, username: "admin", password: "secret", allowNoAuth: false
        );

        Assert.False(ok);
        Assert.Equal(new byte[] { 0x05, 0xFF }, output.ToArray());
    }

    [Fact]
    public void HandleGreeting_ValidCredentials_AuthenticatesSuccessfully()
    {
        var user = "testuser";
        var pass = "testpass";

        // Build client subnegotiation payload: [VER: 0x01, ULEN: len, UBYTES, PLEN: len, PBYTES]
        using var input = new MemoryStream();
        input.WriteByte(0x01);
        input.WriteByte((byte)user.Length);
        input.Write(Encoding.UTF8.GetBytes(user));
        input.WriteByte((byte)pass.Length);
        input.Write(Encoding.UTF8.GetBytes(pass));
        input.Position = 0;

        using var output = new MemoryStream();
        var methods = new byte[] { 0x00, 0x02 }; // Client supports USER/PASS (0x02)

        var ok = LocalProxyAuth.HandleGreeting(
            methods, input, output, username: user, password: pass, allowNoAuth: false
        );

        Assert.True(ok);
        var bytes = output.ToArray();
        // Server response: [0x05, 0x02] for method selection, then [0x01, 0x00] for auth success
        Assert.Equal(new byte[] { 0x05, 0x02, 0x01, 0x00 }, bytes);
    }

    [Fact]
    public void HandleGreeting_WrongPassword_RejectsWithFailure()
    {
        var user = "testuser";
        var expectedPass = "secret123";
        var wrongPass = "wrongpassword";

        using var input = new MemoryStream();
        input.WriteByte(0x01);
        input.WriteByte((byte)user.Length);
        input.Write(Encoding.UTF8.GetBytes(user));
        input.WriteByte((byte)wrongPass.Length);
        input.Write(Encoding.UTF8.GetBytes(wrongPass));
        input.Position = 0;

        using var output = new MemoryStream();
        var methods = new byte[] { 0x02 };

        var ok = LocalProxyAuth.HandleGreeting(
            methods, input, output, username: user, password: expectedPass, allowNoAuth: false
        );

        Assert.False(ok);
        var bytes = output.ToArray();
        // Server response: [0x05, 0x02] for method selection, then [0x01, 0x01] for auth failure
        Assert.Equal(new byte[] { 0x05, 0x02, 0x01, 0x01 }, bytes);
    }
}
