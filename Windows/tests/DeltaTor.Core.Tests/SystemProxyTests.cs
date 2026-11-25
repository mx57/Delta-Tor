using DeltaTor.Core;
using Xunit;

namespace DeltaTor.Core.Tests;

public class SystemProxyTests
{
    [Fact]
    public void IsApplied_InitiallyFalse()
    {
        Assert.False(SystemProxy.IsApplied);
    }

    [Fact]
    public void RestoreIfCrashed_WhenNoBackup_DoesNotThrow()
    {
        var ex = Record.Exception(() => SystemProxy.RestoreIfCrashed());
        Assert.Null(ex);
    }
}
