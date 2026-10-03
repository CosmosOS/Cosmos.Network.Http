// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// Certificates made up for the tests with the desktop's own cryptography:
/// roots, intermediates and server certificates, each as broken as a test
/// needs it. Keys are P-256 unless told otherwise, which is quick to
/// generate; signatures are SHA-256 unless told otherwise.
/// </summary>
internal static class TestPki
{
    public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    /// <summary>A self-signed root, valid from a year ago to a year ahead unless told otherwise.</summary>
    public static X509Certificate2 Root(string name = "Test Root", AsymmetricAlgorithm? key = null,
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null) =>
        Create($"CN={name}", issuer: null, isAuthority: true, key: key,
            notBefore: notBefore ?? DateTimeOffset.UtcNow.AddDays(-365), notAfter: notAfter ?? DateTimeOffset.UtcNow.AddDays(365));

    /// <summary>An intermediate certificate authority.</summary>
    public static X509Certificate2 Authority(X509Certificate2 issuer, string name = "Test Intermediate", int? pathLength = null,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, string[]? usages = null,
        IEnumerable<X509Extension>? extensions = null, AsymmetricAlgorithm? key = null, HashAlgorithmName? hash = null) =>
        Create($"CN={name}", issuer, isAuthority: true, pathLength: pathLength, keyUsage: keyUsage, usages: usages,
            extensions: extensions, key: key, hash: hash,
            notBefore: DateTimeOffset.UtcNow.AddDays(-300), notAfter: DateTimeOffset.UtcNow.AddDays(300));

    /// <summary>
    /// A server certificate for <paramref name="names"/>, DNS names or IP
    /// addresses, valid from an hour ago to 30 days ahead unless told
    /// otherwise; self-signed without an issuer.
    /// </summary>
    public static X509Certificate2 Server(X509Certificate2? issuer, string[] names, string[]? usages = null,
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, IEnumerable<X509Extension>? extensions = null,
        bool isAuthority = false, AsymmetricAlgorithm? key = null, HashAlgorithmName? hash = null) =>
        Create($"CN={(names.Length > 0 ? names[0] : "no name")}", issuer, isAuthority, names: names, usages: usages ?? [ServerAuth],
            keyUsage: X509KeyUsageFlags.DigitalSignature, extensions: extensions, key: key, hash: hash,
            notBefore: notBefore ?? DateTimeOffset.UtcNow.AddHours(-1), notAfter: notAfter ?? DateTimeOffset.UtcNow.AddDays(30));

    /// <summary>A name constraints extension (RFC 5280, section 4.2.1.10) on DNS names, critical as it must be.</summary>
    public static X509Extension NameConstraints(string[] permitted, string[] excluded)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            WriteSubtrees(writer, 0, permitted);
            WriteSubtrees(writer, 1, excluded);
        }

        return new X509Extension("2.5.29.30", writer.Encode(), critical: true);
    }

    /// <summary>An extension nobody understands, critical, which must make a certificate refused.</summary>
    public static X509Extension UnknownCritical() => new("1.3.6.1.4.1.99999.1", [0x05, 0x00], critical: true);

    public static Org.BouncyCastle.X509.X509Certificate ToBouncyCastle(X509Certificate2 certificate) => new(certificate.RawData);

    private static void WriteSubtrees(AsnWriter writer, int tag, string[] names)
    {
        if (names.Length == 0)
        {
            return;
        }

        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tag)))
        {
            foreach (string name in names)
            {
                using (writer.PushSequence())
                {
                    // dNSName is [2] IA5String.
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, name, new Asn1Tag(TagClass.ContextSpecific, 2));
                }
            }
        }
    }

    private static X509Certificate2 Create(string subject, X509Certificate2? issuer, bool isAuthority,
        DateTimeOffset notBefore, DateTimeOffset notAfter, int? pathLength = null,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
        string[]? names = null, string[]? usages = null, IEnumerable<X509Extension>? extensions = null,
        AsymmetricAlgorithm? key = null, HashAlgorithmName? hash = null)
    {
        key ??= ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = key is RSA rsa
            ? new CertificateRequest(subject, rsa, hash ?? HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new CertificateRequest(subject, (ECDsa)key, hash ?? HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isAuthority, pathLength.HasValue, pathLength ?? 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        if (names is { Length: > 0 })
        {
            SubjectAlternativeNameBuilder alternativeNames = new();
            foreach (string name in names)
            {
                if (IPAddress.TryParse(name, out IPAddress? address))
                {
                    alternativeNames.AddIpAddress(address);
                }
                else
                {
                    alternativeNames.AddDnsName(name);
                }
            }

            request.CertificateExtensions.Add(alternativeNames.Build());
        }

        if (usages is not null)
        {
            OidCollection oids = [];
            foreach (string usage in usages)
            {
                oids.Add(new Oid(usage));
            }

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, critical: false));
        }

        if (extensions is not null)
        {
            foreach (X509Extension extension in extensions)
            {
                request.CertificateExtensions.Add(extension);
            }
        }

        if (issuer is null)
        {
            return request.CreateSelfSigned(notBefore, notAfter);
        }

        // Signed through a generator rather than Create(issuer, ...), which
        // refuses an issuer that is no authority: some tests need one.
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        X509SignatureGenerator generator = issuer.GetRSAPrivateKey() is RSA issuerRsa
            ? hash == HashAlgorithmName.SHA1
                ? new Sha1RsaSignatureGenerator(issuerRsa)
                : X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1)
            : X509SignatureGenerator.CreateForECDsa(issuer.GetECDsaPrivateKey()!);
        using X509Certificate2 issued = request.Create(issuer.SubjectName, generator, notBefore, notAfter, serial);
        return key is RSA rsaKey ? issued.CopyWithPrivateKey(rsaKey) : issued.CopyWithPrivateKey((ECDsa)key);
    }

    /// <summary>Signs with SHA-1 and RSA, which the desktop's own generators refuse to do any more.</summary>
    private sealed class Sha1RsaSignatureGenerator(RSA key) : X509SignatureGenerator
    {
        // AlgorithmIdentifier { sha1WithRSAEncryption, NULL }
        private static readonly byte[] s_sha1WithRsa = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00];

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) => s_sha1WithRsa;

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
            key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        protected override PublicKey BuildPublicKey() => new(key);
    }
}
