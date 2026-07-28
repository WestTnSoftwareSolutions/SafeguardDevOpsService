using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneIdentity.DevOps.Data;
using OneIdentity.DevOps.Logic;
using Serilog;
using Xunit;

namespace SafeguardDevOpsService.Tests
{
    public class CertificateHelperTests
    {
        private const string SafeguardDnsName = "tenant.example.safeguardondemand.com";
        private readonly ILogger _logger = new LoggerConfiguration().CreateLogger();

        [Fact]
        public void SystemTrustedCertificateWithNoPolicyErrorsSucceeds()
        {
            using var certificate = CreateServerCertificate(SafeguardDnsName);

            var result = Validate(certificate, SslPolicyErrors.None, true);

            Assert.True(result);
        }

        [Fact]
        public void SystemTrustRejectsUntrustedRoot()
        {
            using var certificate = CreateServerCertificate(SafeguardDnsName);

            var result = Validate(certificate, SslPolicyErrors.RemoteCertificateChainErrors, true);

            Assert.False(result);
        }

        [Fact]
        public void SystemTrustRejectsHostnameMismatch()
        {
            using var certificate = CreateServerCertificate("different.example.com");

            var result = Validate(certificate, SslPolicyErrors.RemoteCertificateNameMismatch, true);

            Assert.False(result);
        }

        [Fact]
        public void ExpiredCertificateIsRejected()
        {
            using var certificate = CreateServerCertificate(SafeguardDnsName,
                DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
            var trustedCertificates = new[] { ToTrustedCertificate(certificate) };

            var result = CertificateHelper.CertificateValidation(certificate, null,
                SslPolicyErrors.RemoteCertificateChainErrors, _logger, true, SafeguardDnsName,
                trustedCertificates);

            Assert.False(result);
        }

        [Fact]
        public void ExistingCustomTrustAcceptsExplicitlyTrustedSelfSignedCertificate()
        {
            using var certificate = CreateServerCertificate(SafeguardDnsName);
            var trustedCertificates = new[] { ToTrustedCertificate(certificate) };

            var result = CertificateHelper.CertificateValidation(certificate, null,
                SslPolicyErrors.RemoteCertificateChainErrors, _logger, false, SafeguardDnsName,
                trustedCertificates);

            Assert.True(result);
        }

        [Fact]
        public void IntermediateRotationDoesNotCauseLockoutUnderSystemTrust()
        {
            using var firstChainCertificate = CreateServerCertificate(SafeguardDnsName);
            using var rotatedChainCertificate = CreateServerCertificate(SafeguardDnsName);

            Assert.NotEqual(firstChainCertificate.Thumbprint, rotatedChainCertificate.Thumbprint);
            Assert.True(Validate(firstChainCertificate, SslPolicyErrors.None, true));
            Assert.True(Validate(rotatedChainCertificate, SslPolicyErrors.None, true));
        }

        private bool Validate(X509Certificate2 certificate, SslPolicyErrors errors, bool trustSystemStore)
        {
            return CertificateHelper.CertificateValidation(certificate, null, errors, _logger,
                trustSystemStore, SafeguardDnsName, Array.Empty<TrustedCertificate>());
        }

        private static TrustedCertificate ToTrustedCertificate(X509Certificate2 certificate)
        {
            return new TrustedCertificate
            {
                Thumbprint = certificate.Thumbprint,
                Subject = certificate.Subject,
                Base64CertificateData = certificate.ExportCertificatePem()
            };
        }

        private static X509Certificate2 CreateServerCertificate(string dnsName,
            DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={dnsName}", rsa, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dnsName);
            request.CertificateExtensions.Add(san.Build());

            return request.CreateSelfSigned(notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-1),
                notAfter ?? DateTimeOffset.UtcNow.AddDays(30));
        }
    }
}
