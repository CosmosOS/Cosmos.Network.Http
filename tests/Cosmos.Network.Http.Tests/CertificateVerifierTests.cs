// Cosmos: tests of the certificate check mbedTLS runs natively for nanoFramework, which the port does itself.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace Cosmos.Network.Http.Tests
{
    [TestClass]
    public class CertificateVerifierTests
    {
        private static BcCertificate[] Trusted => new[] { TestCertificates.Root.Certificate };

        private static string Verify(string host, params TestCertificate[] chain)
        {
            return CertificateVerifier.Verify(Array.ConvertAll(chain, c => c.Certificate), host, Trusted, DateTime.UtcNow);
        }

        [TestMethod]
        public void Leaf_IssuedByTrustedRoot_IsValid()
        {
            Assert.IsNull(Verify("localhost", TestCertificates.RsaServer));
        }

        [TestMethod]
        public void Leaf_WithRootInChain_IsValid()
        {
            Assert.IsNull(Verify("localhost", TestCertificates.EcServer, TestCertificates.Root));
        }

        [TestMethod]
        public void Leaf_ThroughIntermediate_IsValid()
        {
            TestCertificate leaf = TestCertificates.CreateServer("www.example.com", TestCertificates.Intermediate, TestCertificates.Ec(), new[] { "www.example.com" }, null);

            Assert.IsNull(Verify("www.example.com", leaf, TestCertificates.Intermediate));
        }

        [TestMethod]
        public void Leaf_WithoutItsIntermediate_IsRefused()
        {
            TestCertificate leaf = TestCertificates.CreateServer("www.example.com", TestCertificates.Intermediate, TestCertificates.Ec(), new[] { "www.example.com" }, null);

            Assert.IsNotNull(Verify("www.example.com", leaf));
        }

        [TestMethod]
        public void Leaf_IssuedByUntrustedRoot_IsRefused()
        {
            TestCertificate leaf = TestCertificates.CreateServer("localhost", TestCertificates.OtherRoot, TestCertificates.Ec(), new[] { "localhost" }, null);

            Assert.IsNotNull(Verify("localhost", leaf));
            Assert.IsNotNull(Verify("localhost", leaf, TestCertificates.OtherRoot));
        }

        [TestMethod]
        public void SelfSigned_Untrusted_IsRefused()
        {
            TestCertificate self = TestCertificates.CreateServer("localhost", null, TestCertificates.Ec(), new[] { "localhost" }, null);

            Assert.IsNotNull(Verify("localhost", self));
        }

        [TestMethod]
        public void SelfSigned_Trusted_IsValid()
        {
            TestCertificate self = TestCertificates.CreateServer("localhost", null, TestCertificates.Ec(), new[] { "localhost" }, null);

            Assert.IsNull(CertificateVerifier.Verify(new[] { self.Certificate }, "localhost", new[] { self.Certificate }, DateTime.UtcNow));
        }

        [TestMethod]
        public void Leaf_SignedByNonAuthority_IsRefused()
        {
            // The server certificate, whose basicConstraints say it is no authority, signs another.
            TestCertificate leaf = TestCertificates.CreateServer("evil.example.com", TestCertificates.RsaServer, TestCertificates.Ec(), new[] { "evil.example.com" }, null);

            string error = Verify("evil.example.com", leaf, TestCertificates.RsaServer);
            Assert.IsNotNull(error);
        }

        [TestMethod]
        public void Host_NotNamed_IsRefused()
        {
            string error = Verify("example.com", TestCertificates.RsaServer);
            Assert.IsNotNull(error);
            StringAssert.Contains(error, "example.com");
        }

        [TestMethod]
        public void Host_IpAddress_MatchesIpSan()
        {
            Assert.IsNull(Verify("127.0.0.1", TestCertificates.RsaServer));
            Assert.IsNotNull(Verify("127.0.0.2", TestCertificates.RsaServer));
        }

        [TestMethod]
        public void Host_IpAddress_DoesNotMatchDnsName()
        {
            TestCertificate leaf = TestCertificates.CreateServer("10.0.2.2", TestCertificates.Root, TestCertificates.Ec(), new[] { "10.0.2.2" }, null);

            Assert.IsNotNull(Verify("10.0.2.2", leaf));
        }

        [TestMethod]
        public void CommonName_CountsOnlyWithoutDnsNames()
        {
            TestCertificate cnOnly = TestCertificates.CreateServer("cn.example.com", TestCertificates.Root, TestCertificates.Ec(), null, null);
            Assert.IsNull(Verify("cn.example.com", cnOnly));

            TestCertificate withSan = TestCertificates.CreateServer("cn.example.com", TestCertificates.Root, TestCertificates.Ec(), new[] { "san.example.com" }, null);
            Assert.IsNotNull(Verify("cn.example.com", withSan));
            Assert.IsNull(Verify("san.example.com", withSan));
        }

        [TestMethod]
        public void Expired_IsRefused()
        {
            TestCertificate expired = TestCertificates.Create("localhost", TestCertificates.Root, TestCertificates.Ec(), false, new[] { "localhost" }, null,
                KeyPurposeID.id_kp_serverAuth, DateTime.UtcNow.AddDays(-30), DateTime.UtcNow.AddDays(-1));

            string error = Verify("localhost", expired);
            Assert.IsNotNull(error);
            StringAssert.Contains(error, "expired");
        }

        [TestMethod]
        public void NotYetValid_IsRefused()
        {
            TestCertificate future = TestCertificates.Create("localhost", TestCertificates.Root, TestCertificates.Ec(), false, new[] { "localhost" }, null,
                KeyPurposeID.id_kp_serverAuth, DateTime.UtcNow.AddDays(1), DateTime.UtcNow.AddDays(30));

            Assert.IsNotNull(Verify("localhost", future));
        }

        [TestMethod]
        public void ClientCertificate_AsServer_IsRefused()
        {
            // Its extended key usage says clientAuth only.
            Assert.IsNotNull(Verify("Cosmos Test Client", TestCertificates.Client));
        }

        [TestMethod]
        public void ClientCertificate_AsClient_IsValid()
        {
            Assert.IsNull(Verify(null, TestCertificates.Client));
            Assert.IsNotNull(Verify(null, TestCertificates.RsaServer));
        }

        [TestMethod]
        public void NoCertificate_IsRefused()
        {
            Assert.IsNotNull(CertificateVerifier.Verify(new BcCertificate[0], "localhost", Trusted, DateTime.UtcNow));
            Assert.IsNotNull(CertificateVerifier.Verify(null, "localhost", Trusted, DateTime.UtcNow));
        }

        [TestMethod]
        public void PathLength_Exceeded_IsRefused()
        {
            // A root that may issue end-entity certificates only (pathLenConstraint 0), above an intermediate.
            TestCertificate root = TestCertificates.Create("Cosmos PathLen Root", null, TestCertificates.Ec(), true, null, null, null,
                DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1), pathLength: 0);
            TestCertificate intermediate = TestCertificates.CreateAuthority("Cosmos PathLen Intermediate", root, TestCertificates.Ec());
            TestCertificate leaf = TestCertificates.CreateServer("www.example.com", intermediate, TestCertificates.Ec(), new[] { "www.example.com" }, null);
            TestCertificate direct = TestCertificates.CreateServer("www.example.com", root, TestCertificates.Ec(), new[] { "www.example.com" }, null);

            BcCertificate[] trusted = { root.Certificate };
            string error = CertificateVerifier.Verify(new[] { leaf.Certificate, intermediate.Certificate }, "www.example.com", trusted, DateTime.UtcNow);
            Assert.IsNotNull(error);
            StringAssert.Contains(error, "intermediate");

            Assert.IsNull(CertificateVerifier.Verify(new[] { direct.Certificate }, "www.example.com", trusted, DateTime.UtcNow));
        }

        [TestMethod]
        public void CriticalNameConstraints_AreRefused()
        {
            // An intermediate restricted to example.org by a critical nameConstraints, which isn't enforced here.
            TestCertificate intermediate = TestCertificates.Create("Cosmos Constrained Intermediate", TestCertificates.Root, TestCertificates.Ec(), true, null, null, null,
                DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
                customize: g => g.AddExtension(X509Extensions.NameConstraints, true,
                    new NameConstraints(new[] { new GeneralSubtree(new GeneralName(GeneralName.DnsName, "example.org")) }, null)));
            TestCertificate leaf = TestCertificates.CreateServer("www.example.com", intermediate, TestCertificates.Ec(), new[] { "www.example.com" }, null);

            string error = Verify("www.example.com", leaf, intermediate);
            Assert.IsNotNull(error);
            StringAssert.Contains(error, "critical extension");
        }

        [DataTestMethod]
        [DataRow(new byte[0])]
        [DataRow(new byte[] { 0x04, 0x00 })]
        [DataRow(new byte[] { 0x30, 0x03, 0x82, 0x01 })]
        public void MalformedSubjectAltName_NamesNothing(byte[] value)
        {
            // An extension whose value is empty (BouncyCastle reads no names at all: null), not names, or cut short.
            var extensions = new System.Collections.Generic.Dictionary<DerObjectIdentifier, X509Extension>
            {
                [X509Extensions.SubjectAlternativeName] = new X509Extension(false, new DerOctetString(value)),
            };
            var tbs = NewTbs("CN=localhost", TestCertificates.EcServer.Certificate.SubjectPublicKeyInfo);
            tbs.SetExtensions(new X509Extensions(extensions));
            var leaf = new BcCertificate(new X509CertificateStructure(tbs.GenerateTbsCertificate(), new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256), new DerBitString(new byte[64])));

            Assert.IsFalse(CertificateVerifier.NamesHost(leaf, "localhost"));
            Assert.IsNotNull(CertificateVerifier.Verify(new[] { leaf }, "localhost", Trusted, DateTime.UtcNow));
        }

        private static V3TbsCertificateGenerator NewTbs(string name, SubjectPublicKeyInfo key)
        {
            var tbs = new V3TbsCertificateGenerator();
            tbs.SetSerialNumber(new DerInteger(7));
            tbs.SetIssuer(new X509Name(name));
            tbs.SetSubject(new X509Name(name));
            tbs.SetStartDate(new Time(DateTime.UtcNow.AddDays(-1)));
            tbs.SetEndDate(new Time(DateTime.UtcNow.AddDays(1)));
            tbs.SetSignature(new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256));
            tbs.SetSubjectPublicKeyInfo(key);
            return tbs;
        }

        [TestMethod]
        public void IssuerWithUnreadableKey_IsRefusedWithoutFailing()
        {
            // A certificate the peer sends as the leaf's issuer, whose EC key has no curve: BouncyCastle dereferences
            // null reading it.
            var tbs = NewTbs("CN=Cosmos Curveless", new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey), new byte[65]));
            var curveless = new BcCertificate(new X509CertificateStructure(tbs.GenerateTbsCertificate(), new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256), new DerBitString(new byte[64])));

            Assert.IsFalse(CertificateVerifier.HasReadableKey(curveless));
            Assert.IsTrue(CertificateVerifier.HasReadableKey(TestCertificates.EcServer.Certificate));
            Assert.IsTrue(CertificateVerifier.HasReadableKey(TestCertificates.RsaServer.Certificate));

            TestCertificate leaf = TestCertificates.Create("localhost", null, TestCertificates.Ec(), false, new[] { "localhost" }, null,
                KeyPurposeID.id_kp_serverAuth, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30),
                customize: g => g.SetIssuerDN(new X509Name("CN=Cosmos Curveless")));

            Assert.IsNotNull(CertificateVerifier.Verify(new[] { leaf.Certificate, curveless }, "localhost", new[] { TestCertificates.Root.Certificate }, DateTime.UtcNow));
        }

        [DataTestMethod]
        [DataRow("10.0.2.2", new byte[] { 10, 0, 2, 2 })]
        [DataRow("255.255.255.255", new byte[] { 255, 255, 255, 255 })]
        [DataRow("www.example.co.uk", null)]
        [DataRow("1.2.3", null)]
        [DataRow("1.2.3.4.5", null)]
        [DataRow("1.2.3.256", null)]
        [DataRow("1..3.4", null)]
        [DataRow("::1", null)]
        public void ParseIPv4(string host, byte[] expected)
        {
            byte[] actual = CertificateVerifier.ParseIPv4(host);
            if (expected == null)
            {
                Assert.IsNull(actual);
            }
            else
            {
                CollectionAssert.AreEqual(expected, actual);
            }
        }

        [DataTestMethod]
        [DataRow("*.example.com", "www.example.com", true)]
        [DataRow("*.example.com", "WWW.Example.COM", true)]
        [DataRow("*.example.com", "example.com", false)]
        [DataRow("*.example.com", "a.b.example.com", false)]
        [DataRow("www.example.com.", "www.example.com", true)]
        [DataRow("*.example.com.", "www.example.com", true)]
        [DataRow("www.example.com", "www.example.org", false)]
        [DataRow("w*.example.com", "www.example.com", false)]
        public void DnsName_Matching(string pattern, string host, bool expected)
        {
            Assert.AreEqual(expected, CertificateVerifier.MatchesDnsName(pattern, host));
        }

        [TestMethod]
        public void Host_TrailingDot_IsNamed()
        {
            // A fully qualified host: NamesHost drops the dot before matching.
            Assert.IsTrue(CertificateVerifier.NamesHost(TestCertificates.RsaServer.Certificate, "localhost."));
        }
    }
}
