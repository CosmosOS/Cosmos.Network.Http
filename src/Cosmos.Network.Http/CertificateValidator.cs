// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Cosmos.Network.Http;

/// <summary>
/// Decides whether the certificates an https:// server presented prove it is
/// the host it was asked for: a chain from its certificate to a trusted root,
/// every link signed by the next with a strong algorithm, valid now and
/// allowed to issue what it issued, and a certificate that names the host.
/// </summary>
/// <remarks>
/// <para>
/// What the TLS handshake proves on its own is that the server holds the key
/// of the certificate it sent, and that the key may sign (BouncyCastle checks
/// both). The rest is here, close to what browsers check, and short of it in
/// a few ways: there is no revocation (neither OCSP nor CRLs), no certificate
/// policy, no fetching of an intermediate certificate the server leaves out,
/// and the roots' own name constraints are not applied (none of Mozilla's
/// roots has any). Like browsers, the host is only looked for in the subject
/// alternative names, never in the subject's common name.
/// </para>
/// <para>
/// The chain is built from the certificates the server sent, in any order,
/// and stops at the first certificate a trusted root signed, so a chain that
/// ends with a cross-signed copy of a root still leads to the root itself.
/// </para>
/// <para>
/// The dates are checked last, so a date being the problem means nothing
/// else is: a <see cref="HttpRequest.ServerCertificateValidation"/> that
/// forgives a wrong clock forgives nothing more.
/// </para>
/// </remarks>
internal static class CertificateValidator
{
    /// <summary>The most intermediate certificates a chain may go through.</summary>
    private const int MaxIntermediates = 8;

    /// <summary>The names listed when the certificate names another host.</summary>
    private const int MaxListedNames = 4;

    /// <summary>The shortest RSA key a certificate below the root may have, in bits, as browsers require.</summary>
    private const int MinRsaKeyBits = 2048;

    private static readonly DerObjectIdentifier[] s_understoodCriticalExtensions =
    [
        X509Extensions.BasicConstraints,
        X509Extensions.KeyUsage,
        X509Extensions.ExtendedKeyUsage,
        X509Extensions.SubjectAlternativeName,
        X509Extensions.NameConstraints,
        // Policies constrain what a certificate may be used for beyond
        // TLS server authentication; none is required here, as in browsers.
        X509Extensions.CertificatePolicies,
        X509Extensions.PolicyConstraints,
        X509Extensions.InhibitAnyPolicy,
    ];

    /// <summary>
    /// The algorithms a certificate below the root may be signed with: SHA-2
    /// with RSA (PKCS #1 v1.5 or PSS) or ECDSA, and EdDSA. Not SHA-1 or MD5,
    /// whose signatures can be forged. A root's own signature is not checked.
    /// </summary>
    private static readonly string[] s_strongSignatureAlgorithms =
    [
        "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12", // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13", // sha512WithRSAEncryption
        "1.2.840.113549.1.1.10", // RSASSA-PSS
        "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4", // ecdsa-with-SHA512
        "1.3.101.112", // Ed25519
        "1.3.101.113", // Ed448
    ];

    /// <summary>
    /// Checks the chain <paramref name="presented"/> for <paramref name="host"/>.
    /// </summary>
    /// <param name="presented">The certificates the server sent, its own first.</param>
    /// <param name="host">The host name or IP address the request connected to.</param>
    /// <param name="roots">The roots to trust.</param>
    /// <param name="now">The time the certificates must be valid at, in UTC.</param>
    /// <param name="alert">The TLS alert that tells the server why, when the chain is not trusted.</param>
    /// <returns>Why the chain is not trusted, the first problem found; <see langword="null"/> when it is trusted.</returns>
    public static string? Validate(IReadOnlyList<X509Certificate> presented, string host, TrustedRoots roots, DateTime now, out short alert)
    {
        alert = AlertDescription.bad_certificate;
        if (presented.Count == 0)
        {
            return "the server sent no certificate";
        }

        try
        {
            return Check(presented, host, roots, now, ref alert);
        }
        catch (Exception exception)
        {
            // A malformed extension, name or key, which BouncyCastle throws on.
            alert = AlertDescription.bad_certificate;
            return $"the certificates could not be read: {exception.Message}";
        }
    }

    private static string? Check(IReadOnlyList<X509Certificate> presented, string host, TrustedRoots roots, DateTime now, ref short alert)
    {
        X509Certificate leaf = presented[0];

        string? error = CheckHost(leaf, host)
            ?? CheckServerUsage(leaf, Name(leaf, leaf))
            ?? CheckCriticalExtensions(leaf, Name(leaf, leaf), ref alert);
        if (error is not null)
        {
            return error;
        }

        // The chain from the server's certificate up, without the root.
        List<X509Certificate> path = [leaf];
        bool[] used = new bool[presented.Count];
        used[0] = true;

        // A root that signed the chain but has expired, and how far up the
        // chain it signed: kept in case no other way leads to a root.
        X509Certificate? expiredRoot = null;
        int expiredRootPath = 0;

        X509Certificate current = leaf;
        while (true)
        {
            X509Certificate? root = FindRoot(roots, current, now, out X509Certificate? expired);
            if (root is not null)
            {
                return CheckPath(path, root, host, now, ref alert);
            }

            if (expired is not null && expiredRoot is null)
            {
                expiredRoot = expired;
                expiredRootPath = path.Count;
            }

            int index = path.Count > MaxIntermediates ? -1 : FindIssuer(presented, used, current);
            if (index < 0)
            {
                if (expiredRoot is not null)
                {
                    return CheckPath(path.GetRange(0, expiredRootPath), expiredRoot, host, now, ref alert);
                }

                if (path.Count > MaxIntermediates)
                {
                    return $"the chain goes through more than {MaxIntermediates} intermediate certificates";
                }

                alert = AlertDescription.unknown_ca;
                if (current == leaf)
                {
                    return IsSelfIssued(leaf)
                        ? "the certificate is self-signed"
                        : $"the certificate is issued by {leaf.IssuerDN}, which is not a trusted root: the server may have left out an intermediate certificate";
                }

                return IsSelfIssued(current)
                    ? $"the chain ends with {current.SubjectDN}, which is not a trusted root"
                    : $"the chain goes up to {current.IssuerDN}, which is not a trusted root";
            }

            used[index] = true;
            X509Certificate issuer = presented[index];
            string name = Name(issuer, leaf);

            error = CheckAuthority(issuer, name, path.Count - 1)
                ?? CheckCriticalExtensions(issuer, name, ref alert);
            if (error is not null)
            {
                return error;
            }

            path.Add(issuer);
            current = issuer;
        }
    }

    /// <summary>
    /// What is left to check once <paramref name="root"/> signed the top of
    /// <paramref name="path"/>: signature algorithms and keys, name
    /// constraints, then the dates of everything, the root's included.
    /// </summary>
    private static string? CheckPath(List<X509Certificate> path, X509Certificate root, string host, DateTime now, ref short alert)
    {
        X509Certificate leaf = path[0];
        foreach (X509Certificate certificate in path)
        {
            string? error = CheckSignatureAlgorithm(certificate, Name(certificate, leaf))
                ?? CheckKey(certificate, Name(certificate, leaf));
            if (error is not null)
            {
                return error;
            }
        }

        string? constraints = CheckNameConstraints(path, host);
        if (constraints is not null)
        {
            return constraints;
        }

        foreach (X509Certificate certificate in path)
        {
            string? error = CheckDates(certificate, Name(certificate, leaf), now, ref alert);
            if (error is not null)
            {
                return error;
            }
        }

        return CheckDates(root, $"the root {root.SubjectDN}", now, ref alert);
    }

    /// <summary>How a message calls <paramref name="certificate"/>: "the certificate" for the server's own, its subject otherwise.</summary>
    private static string Name(X509Certificate certificate, X509Certificate leaf) =>
        certificate == leaf ? "the certificate" : certificate.SubjectDN.ToString();

    /// <summary>
    /// A trusted root whose subject is the issuer of <paramref name="certificate"/>
    /// and whose key verifies its signature, valid now; <paramref name="expired"/>
    /// is one that would do but for its dates, when there is no such root.
    /// </summary>
    private static X509Certificate? FindRoot(TrustedRoots roots, X509Certificate certificate, DateTime now, out X509Certificate? expired)
    {
        expired = null;
        foreach (X509Certificate candidate in roots.FindBySubject(certificate.IssuerDN))
        {
            if (!IsSignedBy(certificate, candidate))
            {
                continue;
            }

            if (now >= candidate.NotBefore && now <= candidate.NotAfter)
            {
                return candidate;
            }

            expired ??= candidate;
        }

        return null;
    }

    /// <summary>
    /// The index in <paramref name="presented"/> of an unused certificate
    /// named as the issuer of <paramref name="certificate"/> and whose key
    /// verifies its signature, or -1.
    /// </summary>
    private static int FindIssuer(IReadOnlyList<X509Certificate> presented, bool[] used, X509Certificate certificate)
    {
        byte[] issuerName = certificate.IssuerDN.GetEncoded();
        for (int i = 0; i < presented.Count; i++)
        {
            if (!used[i]
                && Arrays.AreEqual(presented[i].SubjectDN.GetEncoded(), issuerName)
                && IsSignedBy(certificate, presented[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool IsSignedBy(X509Certificate certificate, X509Certificate issuer)
    {
        try
        {
            return certificate.IsSignatureValid(issuer.GetPublicKey());
        }
        catch (Exception)
        {
            // A key or signature algorithm the other does not go with.
            return false;
        }
    }

    private static bool IsSelfIssued(X509Certificate certificate) =>
        Arrays.AreEqual(certificate.SubjectDN.GetEncoded(), certificate.IssuerDN.GetEncoded());

    private static string? CheckSignatureAlgorithm(X509Certificate certificate, string name) =>
        Array.IndexOf(s_strongSignatureAlgorithms, certificate.SigAlgOid) >= 0
            ? null
            : $"{name} is signed with {certificate.SigAlgName}, which is too weak to trust";

    private static string? CheckKey(X509Certificate certificate, string name) =>
        certificate.GetPublicKey() is RsaKeyParameters rsa && rsa.Modulus.BitLength < MinRsaKeyBits
            ? $"{name} has a {rsa.Modulus.BitLength}-bit RSA key, shorter than the {MinRsaKeyBits} bits required"
            : null;

    private static string? CheckDates(X509Certificate certificate, string name, DateTime now, ref short alert)
    {
        if (now < certificate.NotBefore)
        {
            alert = AlertDescription.certificate_unknown;
            return $"{name} is not valid before {Format(certificate.NotBefore)} (is the clock right? it reads {Format(now)})";
        }

        if (now > certificate.NotAfter)
        {
            alert = AlertDescription.certificate_expired;
            return $"{name} expired on {Format(certificate.NotAfter)}";
        }

        return null;
    }

    private static string Format(DateTime time) =>
        time.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    /// <summary>
    /// Whether <paramref name="issuer"/> may issue the chain below it: a
    /// certificate authority, allowed to sign certificates, whose path length
    /// constraint leaves room for the <paramref name="intermediatesBelow"/>
    /// intermediates under it, and not restricted to other uses than TLS
    /// servers.
    /// </summary>
    private static string? CheckAuthority(X509Certificate issuer, string name, int intermediatesBelow)
    {
        int pathLength = issuer.GetBasicConstraints();
        if (pathLength < 0)
        {
            return $"{name} issued part of the chain but is not a certificate authority";
        }

        if (intermediatesBelow > pathLength)
        {
            return $"{name} allows {pathLength} intermediate certificates under it, and the chain has {intermediatesBelow}";
        }

        bool[]? keyUsage = issuer.GetKeyUsage();
        if (keyUsage is not null && !keyUsage[5])
        {
            return $"{name} issued part of the chain but its key may not sign certificates";
        }

        return CheckServerUsage(issuer, name);
    }

    /// <summary>Whether the extended key usage, if any, allows TLS servers: browsers apply it to intermediates too.</summary>
    private static string? CheckServerUsage(X509Certificate certificate, string name)
    {
        IList<DerObjectIdentifier>? usages = certificate.GetExtendedKeyUsage();
        if (usages is null || usages.Contains(KeyPurposeID.id_kp_serverAuth) || usages.Contains(KeyPurposeID.AnyExtendedKeyUsage))
        {
            return null;
        }

        return $"{name} is not for TLS servers";
    }

    private static string? CheckCriticalExtensions(X509Certificate certificate, string name, ref short alert)
    {
        ISet<string>? critical = certificate.GetCriticalExtensionOids();
        if (critical is null)
        {
            return null;
        }

        foreach (string oid in critical)
        {
            bool understood = false;
            foreach (DerObjectIdentifier known in s_understoodCriticalExtensions)
            {
                if (known.Id == oid)
                {
                    understood = true;
                    break;
                }
            }

            if (!understood)
            {
                alert = AlertDescription.unsupported_certificate;
                return $"{name} has a critical extension that is not understood ({oid})";
            }
        }

        return null;
    }

    /// <summary>
    /// Applies the name constraints of the intermediates on
    /// <paramref name="path"/> (the server's certificate first) to the
    /// certificates below each, from the top down (RFC 5280, section 6.1),
    /// and to <paramref name="host"/> itself: a wildcard name could otherwise
    /// cover a host its issuer may not certify.
    /// </summary>
    private static string? CheckNameConstraints(List<X509Certificate> path, string host)
    {
        PkixNameConstraintValidator validator = new();
        bool constrained = false;
        for (int i = path.Count - 1; i >= 0; i--)
        {
            X509Certificate certificate = path[i];
            bool isLeaf = i == 0;

            // Self-issued intermediates are left out of the check (section 4.2.1.10).
            if (constrained && (isLeaf || !IsSelfIssued(certificate)))
            {
                try
                {
                    validator.CheckDN(certificate.SubjectDN);
                    GeneralNames? names = certificate.GetSubjectAlternativeNameExtension();
                    if (names is not null)
                    {
                        foreach (GeneralName name in names.GetNames())
                        {
                            validator.CheckName(name);
                        }
                    }

                    if (isLeaf)
                    {
                        validator.CheckName(IPAddress.TryParse(host, out _)
                            ? new GeneralName(GeneralName.IPAddress, host)
                            : new GeneralName(GeneralName.DnsName, host.TrimEnd('.')));
                    }
                }
                catch (PkixNameConstraintValidatorException exception)
                {
                    return $"{certificate.SubjectDN} is outside the names its issuer may certify: {exception.Message}";
                }
            }

            if (isLeaf)
            {
                break;
            }

            Asn1Object? value = certificate.GetExtensionParsedValue(X509Extensions.NameConstraints);
            if (value is null)
            {
                continue;
            }

            NameConstraints constraints = NameConstraints.GetInstance(value);
            if (constraints.PermittedSubtreesValue is GeneralSubtrees permitted)
            {
                validator.IntersectPermittedSubtree(permitted.Elements);
                constrained = true;
            }

            if (constraints.ExcludedSubtreesValue is GeneralSubtrees excluded)
            {
                foreach (GeneralSubtree subtree in excluded.GetElements())
                {
                    validator.AddExcludedSubtree(subtree);
                }

                constrained = true;
            }
        }

        return null;
    }

    /// <summary>
    /// Whether the certificate's subject alternative names name
    /// <paramref name="host"/>: as an IP address when the host is one,
    /// otherwise as a DNS name (RFC 6125), with a wildcard allowed as the
    /// whole left-most label.
    /// </summary>
    private static string? CheckHost(X509Certificate certificate, string host)
    {
        GeneralNames? names = certificate.GetSubjectAlternativeNameExtension();
        if (names is null)
        {
            return $"the certificate names no host (it has no subject alternative names), so not {host}";
        }

        bool isAddress = IPAddress.TryParse(host, out IPAddress? address);
        List<string> listed = [];
        foreach (GeneralName name in names.GetNames())
        {
            if (name.TagNo == GeneralName.IPAddress)
            {
                byte[] bytes = Asn1OctetString.GetInstance(name.Name).GetOctets();
                if (isAddress && Arrays.AreEqual(bytes, address!.GetAddressBytes()))
                {
                    return null;
                }

                if (bytes.Length is 4 or 16)
                {
                    listed.Add(new IPAddress(bytes).ToString());
                }
            }
            else if (name.TagNo == GeneralName.DnsName)
            {
                string pattern = ((IAsn1String)name.Name).GetString();
                if (!isAddress && MatchesDnsName(pattern, host))
                {
                    return null;
                }

                listed.Add(pattern);
            }
        }

        if (listed.Count == 0)
        {
            return $"the certificate names no host, so not {host}";
        }

        StringBuilder message = new("the certificate is for ");
        for (int i = 0; i < listed.Count && i < MaxListedNames; i++)
        {
            message.Append(i == 0 ? "" : ", ").Append(listed[i]);
        }

        if (listed.Count > MaxListedNames)
        {
            message.Append(" and ").Append(listed.Count - MaxListedNames).Append(" more");
        }

        return message.Append(", not ").Append(host).ToString();
    }

    /// <summary>
    /// Whether <paramref name="pattern"/>, a DNS name from a certificate,
    /// names <paramref name="host"/>: alike but for case, or with a
    /// <c>*</c> as the whole left-most label standing for exactly one label
    /// of the host, under at least two labels (never <c>*.com</c>). There is
    /// no public suffix list: that <c>*.co.uk</c> is never issued is left to
    /// the certificate authorities, which may not issue it.
    /// </summary>
    internal static bool MatchesDnsName(string pattern, string host)
    {
        pattern = pattern.TrimEnd('.');
        host = host.TrimEnd('.');
        if (pattern.Length == 0 || host.Length == 0)
        {
            return false;
        }

        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return pattern.Equals(host, StringComparison.OrdinalIgnoreCase);
        }

        string suffix = pattern.Substring(1);
        int firstDot = host.IndexOf('.');
        return suffix.IndexOf('.', 1) > 0
            && suffix.IndexOf('*') < 0
            && firstDot > 0
            && host.Substring(firstDot).Equals(suffix, StringComparison.OrdinalIgnoreCase);
    }
}
