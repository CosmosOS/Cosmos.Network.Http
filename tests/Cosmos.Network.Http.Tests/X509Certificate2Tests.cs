// Cosmos: tests of what nanoFramework parses natively: certificates and private keys, PEM and DER.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Cosmos.Network.Http.Tests
{
    [TestClass]
    public class X509Certificate2Tests
    {
        private static TestCertificate Rsa => TestCertificates.RsaServer;

        private static TestCertificate Ec => TestCertificates.EcServer;

        [TestMethod]
        public void Certificate_FromPemString_IsParsed()
        {
            var certificate = new X509Certificate(Rsa.Pem);

            StringAssert.Contains(certificate.Subject, "CN=localhost");
            StringAssert.Contains(certificate.Issuer, "CN=Cosmos Test Root");
            Assert.AreEqual(Rsa.Certificate.NotAfter, certificate.GetExpirationDate());
            Assert.AreEqual(Rsa.Certificate.NotBefore, certificate.GetEffectiveDate());
        }

        [TestMethod]
        public void Certificate_FromDer_IsParsed()
        {
            var certificate = new X509Certificate(Rsa.Der);

            StringAssert.Contains(certificate.Subject, "CN=localhost");
            Assert.AreEqual(1, certificate.GetCertificates().Length);
        }

        [TestMethod]
        public void Certificate_DerEndingWithZero_IsParsed()
        {
            // A DER certificate may end with a zero byte, which isn't nanoFramework's string terminator.
            for (int i = 0; i < 2048; i++)
            {
                TestCertificate candidate = TestCertificates.CreateServer("zero" + i, TestCertificates.Root, TestCertificates.Root.Key, null, null);
                byte[] der = candidate.Der;
                if (der[der.Length - 1] == 0)
                {
                    var certificate = new X509Certificate(der);
                    Assert.AreEqual(1, certificate.GetCertificates().Length);
                    CollectionAssert.AreEqual(der, certificate.GetCertificates()[0].GetEncoded());
                    return;
                }
            }

            Assert.Inconclusive("No certificate ending with a zero byte was made.");
        }

        [TestMethod]
        public void Certificate_PemBundle_HoldsEveryCertificate()
        {
            string bundle = TestCertificates.Root.Pem + TestCertificates.OtherRoot.Pem + TestCertificates.Intermediate.Pem;

            var certificate = new X509Certificate(bundle);

            Assert.AreEqual(3, certificate.GetCertificates().Length);
            StringAssert.Contains(certificate.Subject, "CN=Cosmos Test Root");
        }

        [TestMethod]
        public void Certificate_Garbage_Throws()
        {
            Assert.ThrowsException<CryptographicException>(() => new X509Certificate(Encoding.UTF8.GetBytes("not a certificate")));
        }

        [TestMethod]
        public void Key_Pkcs8Pem_IsDecoded()
        {
            AssertSameKey(Rsa, new X509Certificate2(Rsa.Pem, Rsa.KeyPem(), null));
            AssertSameKey(Ec, new X509Certificate2(Ec.Pem, Ec.KeyPem(), null));
        }

        [TestMethod]
        public void Key_TraditionalPem_IsDecoded()
        {
            // "RSA PRIVATE KEY" (PKCS#1) and "EC PRIVATE KEY" (SEC1).
            AssertSameKey(Rsa, new X509Certificate2(Rsa.Pem, Rsa.KeyPem(traditional: true), null));
            AssertSameKey(Ec, new X509Certificate2(Ec.Pem, Ec.KeyPem(traditional: true), null));
        }

        [TestMethod]
        public void Key_EncryptedPkcs8Pem_IsDecoded()
        {
            var writer = new StringWriter();
            new PemWriter(writer).WriteObject(new Pkcs8Generator(Ec.Key.Private, Pkcs8Generator.PbeWithShaAnd3KeyTripleDesCbc) { Password = "secret".ToCharArray() });

            AssertSameKey(Ec, new X509Certificate2(Ec.Pem, writer.ToString(), "secret"));
            Assert.ThrowsException<CryptographicException>(() => new X509Certificate2(Ec.Pem, writer.ToString(), "wrong"));
        }

        [TestMethod]
        public void Key_EncryptedTraditionalPem_IsDecoded()
        {
            var writer = new StringWriter();
            new PemWriter(writer).WriteObject(Rsa.Key.Private, "AES-128-CBC", "secret".ToCharArray(), new SecureRandom());

            AssertSameKey(Rsa, new X509Certificate2(Rsa.Pem, writer.ToString(), "secret"));
        }

        [TestMethod]
        public void Key_Pkcs8Der_IsDecoded()
        {
            byte[] der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(Rsa.Key.Private).GetEncoded();

            AssertSameKey(Rsa, new X509Certificate2(Rsa.Der, der, null));
        }

        [TestMethod]
        public void Key_EncryptedPkcs8Der_IsDecoded()
        {
            byte[] salt = new byte[8];
            new SecureRandom().NextBytes(salt);
            byte[] der = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc, "secret".ToCharArray(), salt, 2048, Ec.Key.Private).GetEncoded();

            AssertSameKey(Ec, new X509Certificate2(Ec.Der, der, "secret"));
        }

        [TestMethod]
        public void Key_Pkcs1Der_IsDecoded()
        {
            byte[] der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(Rsa.Key.Private).ParsePrivateKey().GetEncoded();

            AssertSameKey(Rsa, new X509Certificate2(Rsa.Der, der, null));
        }

        [TestMethod]
        public void Key_Sec1Der_IsDecoded()
        {
            byte[] der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(Ec.Key.Private).ParsePrivateKey().GetEncoded();

            AssertSameKey(Ec, new X509Certificate2(Ec.Der, der, null));
        }

        [TestMethod]
        public void Key_DerWithTerminator_IsDecoded()
        {
            byte[] der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(Ec.Key.Private).GetEncoded();
            byte[] terminated = new byte[der.Length + 1];
            Array.Copy(der, terminated, der.Length);

            AssertSameKey(Ec, new X509Certificate2(Ec.Der, terminated, null));
        }

        [TestMethod]
        public void Key_EcWithoutCurve_Throws()
        {
            // SEC1 lets the curve be left out (RFC 5915), which BouncyCastle can't build a key without.
            var ec = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)Ec.Key.Private;
            byte[] der = new Org.BouncyCastle.Asn1.Sec.ECPrivateKeyStructure(256, ec.D).GetEncoded();

            Assert.ThrowsException<CryptographicException>(() => new X509Certificate2(Ec.Der, der, null));

            var writer = new StringWriter();
            new Org.BouncyCastle.Utilities.IO.Pem.PemWriter(writer).WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("EC PRIVATE KEY", der));
            Assert.ThrowsException<CryptographicException>(() => new X509Certificate2(Ec.Pem, writer.ToString(), null));
        }

        [TestMethod]
        public void Key_PemAfterParameters_IsDecoded()
        {
            // As openssl ecparam -genkey writes it: the curve's block first, then the key's.
            string pem = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" + Ec.KeyPem(traditional: true);

            AssertSameKey(Ec, new X509Certificate2(Ec.Pem, pem, null));
        }

        [TestMethod]
        public void Key_Garbage_Throws()
        {
            Assert.ThrowsException<CryptographicException>(() => new X509Certificate2(Rsa.Pem, "not a key", null));
        }

        private static void AssertSameKey(TestCertificate expected, X509Certificate2 certificate)
        {
            Assert.IsTrue(certificate.HasPrivateKey);
            Assert.IsNotNull(certificate.Key);
            Assert.IsTrue(certificate.Key.IsPrivate);

            switch (expected.Key.Private)
            {
                case RsaPrivateCrtKeyParameters rsa:
                    Assert.AreEqual(rsa.Modulus, ((RsaKeyParameters)certificate.Key).Modulus);
                    Assert.AreEqual(rsa.Exponent, ((RsaKeyParameters)certificate.Key).Exponent);
                    break;

                case ECPrivateKeyParameters ec:
                    Assert.AreEqual(ec.D, ((ECPrivateKeyParameters)certificate.Key).D);
                    break;

                default:
                    Assert.Fail("Unexpected key type " + expected.Key.Private.GetType());
                    break;
            }
        }
    }
}
