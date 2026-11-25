using DeltaTor.Core;
using Xunit;

namespace DeltaTor.Core.Tests;

public class ReleaseCheckerTests
{
    [Theory]
    [InlineData("2.0.0", "2.0.1", -1)]
    [InlineData("2.0.1", "2.0.0", 1)]
    [InlineData("2.0.0", "2.0.0", 0)]
    [InlineData("1.9.9", "2.0.0", -1)]
    [InlineData("2.0", "2.0.0", 0)]
    [InlineData("2.1.0", "2.0.9", 1)]
    [InlineData("3.0.0", "2.9.9", 1)]
    public void CompareVersions_OrdersCorrectly(string v1, string v2, int expectedSign)
    {
        var result = ReleaseChecker.CompareVersions(v1, v2);
        if (expectedSign < 0) Assert.True(result < 0);
        else if (expectedSign > 0) Assert.True(result > 0);
        else Assert.Equal(0, result);
    }
}
