using OneIdentity.DevOps.Logic;
using Xunit;

namespace SafeguardDevOpsService.Tests
{
    public class CertificateHelperTests
    {
        [Theory]
        [InlineData(null, null, true, true)]
        [InlineData(null, null, false, false)]
        [InlineData(null, false, true, false)]
        [InlineData(null, true, false, true)]
        [InlineData(false, true, true, false)]
        [InlineData(true, false, false, true)]
        public void EffectiveSystemTrustUsesRequestThenConfigurationThenPlatform(
            bool? requested, bool? configured, bool isWindows, bool expected)
        {
            var actual = CertificateHelper.GetEffectiveTrustSystemStore(
                requested, configured, isWindows);

            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(true, false, true)]
        [InlineData(false, true, true)]
        [InlineData(true, true, true)]
        [InlineData(false, false, false)]
        public void TlsRequiresSystemTrustOrLegacyCertificates(
            bool trustSystemStore, bool hasTrustedCertificates, bool expected)
        {
            Assert.Equal(expected, CertificateHelper.HasCertificateTrustSource(
                trustSystemStore, hasTrustedCertificates));
        }
    }
}
