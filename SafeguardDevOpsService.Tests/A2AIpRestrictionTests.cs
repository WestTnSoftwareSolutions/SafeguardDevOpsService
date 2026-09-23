using OneIdentity.DevOps.Logic;
using Xunit;

namespace SafeguardDevOpsService.Tests
{
    public class A2AIpRestrictionTests
    {
        [Theory]
        [InlineData("203.0.113.10", "203.0.113.10")]
        [InlineData(" 10.20.0.0/16 ", "10.20.0.0/16")]
        [InlineData("2001:db8::1", "2001:db8::1")]
        [InlineData("2001:db8::/64", "2001:db8::/64")]
        public void NormalizesValidIpAndCidrRestrictions(string value, string expected)
        {
            Assert.True(SafeguardLogic.TryNormalizeIpRestriction(value, out var actual));
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("not-an-address")]
        [InlineData("10.0.0.1/33")]
        [InlineData("2001:db8::1/129")]
        [InlineData("10.0.0.1/24/2")]
        public void RejectsInvalidIpAndCidrRestrictions(string value)
        {
            Assert.False(SafeguardLogic.TryNormalizeIpRestriction(value, out _));
        }
    }
}
