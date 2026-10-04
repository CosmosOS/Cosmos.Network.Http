// Cosmos: certificates for the TLS tests, made with BouncyCastle as the port's TLS runs on it. nanoFramework's tests
// have none, as its TLS is native.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace Cosmos.Network.Http.Tests
{
    /// <summary>
    /// A certificate and its private key.
    /// </summary>
    internal sealed class TestCertificate
    {
        internal TestCertificate(BcCertificate certificate, AsymmetricKeyPair key)
        {
            Certificate = certificate;
            Key = key;
        }

        internal BcCertificate Certificate { get; }

        internal AsymmetricKeyPair Key { get; }

        internal byte[] Der => Certificate.GetEncoded();

        internal string Pem
        {
            get
            {
                var writer = new StringWriter();
                new PemWriter(writer).WriteObject(Certificate);
                return writer.ToString();
            }
        }

        /// <summary>
        /// The private key as PEM: PKCS#8, or PKCS#1/SEC1 when <paramref name="traditional"/>.
        /// </summary>
        internal string KeyPem(bool traditional = false)
        {
            var writer = new StringWriter();
            if (traditional)
            {
                new PemWriter(writer).WriteObject(Key.Private);
            }
            else
            {
                new PemWriter(writer).WriteObject(new Pkcs8Generator(Key.Private));
            }

            return writer.ToString();
        }

        /// <summary>
        /// The certificate with its private key, as a TLS peer uses it.
        /// </summary>
        internal X509Certificate2 WithKey() => new X509Certificate2(Pem, KeyPem(), null);

        /// <summary>
        /// The certificate alone, as a trusted one.
        /// </summary>
        internal X509Certificate Public() => new X509Certificate(Der);
    }

    internal sealed class AsymmetricKeyPair
    {
        internal AsymmetricKeyPair(AsymmetricCipherKeyPair pair, string signatureAlgorithm)
        {
            Public = pair.Public;
            Private = pair.Private;
            SignatureAlgorithm = signatureAlgorithm;
        }

        internal AsymmetricKeyParameter Public { get; }

        internal AsymmetricKeyParameter Private { get; }

        internal string SignatureAlgorithm { get; }
    }

    internal static class TestCertificates
    {
        private static readonly SecureRandom s_random = new SecureRandom();
        private static long s_serial = 1;

        private static readonly object s_lock = new object();
        private static TestCertificate s_root;
        private static TestCertificate s_otherRoot;
        private static TestCertificate s_intermediate;
        private static TestCertificate s_rsaServer;
        private static TestCertificate s_ecServer;
        private static TestCertificate s_client;

        /// <summary>
        /// A root certificate authority, with an EC P-256 key.
        /// </summary>
        internal static TestCertificate Root => Lazy(ref s_root, () => CreateAuthority("Cosmos Test Root", null, Ec()));

        /// <summary>
        /// A root nobody trusts.
        /// </summary>
        internal static TestCertificate OtherRoot => Lazy(ref s_otherRoot, () => CreateAuthority("Cosmos Other Root", null, Ec()));

        /// <summary>
        /// An intermediate authority under <see cref="Root"/>.
        /// </summary>
        internal static TestCertificate Intermediate => Lazy(ref s_intermediate, () => CreateAuthority("Cosmos Test Intermediate", Root, Ec()));

        /// <summary>
        /// A server certificate for localhost and 127.0.0.1 with an RSA key, issued by <see cref="Root"/>.
        /// </summary>
        internal static TestCertificate RsaServer => Lazy(ref s_rsaServer, () => CreateServer("localhost", Root, Rsa(), new[] { "localhost" }, new[] { "127.0.0.1" }));

        /// <summary>
        /// A server certificate for localhost and 127.0.0.1 with an EC P-256 key, issued by <see cref="Root"/>.
        /// </summary>
        internal static TestCertificate EcServer => Lazy(ref s_ecServer, () => CreateServer("localhost", Root, Ec(), new[] { "localhost" }, new[] { "127.0.0.1" }));

        /// <summary>
        /// A client certificate issued by <see cref="Root"/>.
        /// </summary>
        internal static TestCertificate Client => Lazy(ref s_client, () => Create("Cosmos Test Client", Root, Ec(), false, null, null, KeyPurposeID.id_kp_clientAuth, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30)));

        internal static AsymmetricKeyPair Rsa()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), s_random, 2048, 25));
            return new AsymmetricKeyPair(generator.GenerateKeyPair(), "SHA256WITHRSA");
        }

        internal static AsymmetricKeyPair Ec()
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, s_random));
            return new AsymmetricKeyPair(generator.GenerateKeyPair(), "SHA256WITHECDSA");
        }

        internal static TestCertificate CreateAuthority(string name, TestCertificate issuer, AsymmetricKeyPair key)
        {
            return Create(name, issuer, key, true, null, null, null, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));
        }

        internal static TestCertificate CreateServer(string name, TestCertificate issuer, AsymmetricKeyPair key, string[] dnsNames, string[] addresses)
        {
            return Create(name, issuer, key, false, dnsNames, addresses, KeyPurposeID.id_kp_serverAuth, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
        }

        internal static TestCertificate Create(
            string name,
            TestCertificate issuer,
            AsymmetricKeyPair key,
            bool authority,
            string[] dnsNames,
            string[] addresses,
            KeyPurposeID purpose,
            DateTime notBefore,
            DateTime notAfter,
            int pathLength = -1,
            Action<X509V3CertificateGenerator> customize = null)
        {
            var subject = new X509Name("CN=" + name);

            var generator = new X509V3CertificateGenerator();
            lock (s_lock)
            {
                generator.SetSerialNumber(BigInteger.ValueOf(s_serial++));
            }

            generator.SetSubjectDN(subject);
            generator.SetIssuerDN(issuer != null ? issuer.Certificate.SubjectDN : subject);
            generator.SetNotBefore(notBefore);
            generator.SetNotAfter(notAfter);
            generator.SetPublicKey(key.Public);

            if (authority)
            {
                generator.AddExtension(X509Extensions.BasicConstraints, true, pathLength >= 0 ? new BasicConstraints(pathLength) : new BasicConstraints(true));
                generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            }
            else
            {
                generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
                generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            }

            if (purpose != null)
            {
                generator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(purpose));
            }

            var names = new List<GeneralName>();
            foreach (string dnsName in dnsNames ?? Array.Empty<string>())
            {
                names.Add(new GeneralName(GeneralName.DnsName, dnsName));
            }

            foreach (string address in addresses ?? Array.Empty<string>())
            {
                names.Add(new GeneralName(GeneralName.IPAddress, new DerOctetString(IPAddress.Parse(address).GetAddressBytes())));
            }

            if (names.Count > 0)
            {
                generator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(names.ToArray()));
            }

            customize?.Invoke(generator);

            AsymmetricKeyPair signer = issuer != null ? issuer.Key : key;
            BcCertificate certificate = generator.Generate(new Asn1SignatureFactory(signer.SignatureAlgorithm, signer.Private, s_random));

            return new TestCertificate(certificate, key);
        }

        private static TestCertificate Lazy(ref TestCertificate field, Func<TestCertificate> create)
        {
            lock (s_lock)
            {
                return field ??= create();
            }
        }
    }
}
