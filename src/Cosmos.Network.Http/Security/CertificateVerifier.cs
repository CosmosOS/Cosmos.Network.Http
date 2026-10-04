// Cosmos: the certificate check mbedTLS runs natively for nanoFramework (mbedtls_x509_crt_verify): the chain the peer
// sent must lead to a trusted certificate through valid signatures, every certificate must be within its validity
// period, and a server's must name the host. BouncyCastle's TLS leaves this to its caller.

using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace Cosmos.Network.Http
{
    /// <summary>
    /// Checks a peer's certificate chain.
    /// </summary>
    internal static class CertificateVerifier
    {
        // Longer chains than a leaf, a few intermediates and a root are refused.
        private const int MaxDepth = 8;

        private const int KeyCertSign = 5;

        /// <summary>
        /// Checks a certificate chain.
        /// </summary>
        /// <param name="chain">The certificates the peer sent, its own first.</param>
        /// <param name="host">The host the leaf certificate must name, or null not to check it (a client certificate).</param>
        /// <param name="trusted">The trusted certificates.</param>
        /// <param name="now">The time the certificates must be valid at.</param>
        /// <returns>null if the chain is valid, else why it is not.</returns>
        internal static string Verify(BcCertificate[] chain, string host, IList<BcCertificate> trusted, DateTime now)
        {
            if (chain == null || chain.Length == 0)
            {
                return "The peer sent no certificate.";
            }

            BcCertificate current = chain[0];

            string error = CheckValidity(current, now);
            if (error != null)
            {
                return error;
            }

            if (host != null && !NamesHost(current, host))
            {
                return "The certificate of " + Name(current) + " doesn't name " + host + ".";
            }

            // A server's certificate must be one for servers, a client's one for clients, when it says what it is for.
            KeyPurposeID purpose = host != null ? KeyPurposeID.id_kp_serverAuth : KeyPurposeID.id_kp_clientAuth;
            if (!AllowsPurpose(current, purpose))
            {
                return "The certificate of " + Name(current) + " isn't meant for TLS " + (host != null ? "servers." : "clients.");
            }

            for (int depth = 0; depth < MaxDepth; depth++)
            {
                // Refused as mbedTLS refuses it: an extension it can't honour that says it must be.
                error = CheckCriticalExtensions(current);
                if (error != null)
                {
                    return error;
                }

                // A certificate trusted as such: the end of the chain.
                if (Contains(trusted, current))
                {
                    return null;
                }

                // Signed by a trusted certificate. Above the leaf, depth certificate authorities stand below it.
                BcCertificate anchor = FindIssuer(current, trusted, 0, now, depth, out error);
                if (anchor != null)
                {
                    return null;
                }

                // Signed by an intermediate the peer sent.
                BcCertificate issuer = FindIssuer(current, chain, 1, now, depth, out string chainError);
                if (issuer == null || issuer.Equals(current))
                {
                    // No issuer, or a self-signed root the peer sent that isn't trusted.
                    return error ?? chainError ?? "The certificate of " + Name(current) + " was issued by " + current.IssuerDN + ", which isn't trusted.";
                }

                current = issuer;
            }

            return "The certificate chain is longer than " + MaxDepth + " certificates.";
        }

        /// <summary>
        /// Whether a server certificate names a host, by its subjectAltName (dNSName or iPAddress), else its common name.
        /// </summary>
        internal static bool NamesHost(BcCertificate certificate, string host)
        {
            host = host.TrimEnd('.');

            byte[] address = ParseIPv4(host);

            bool hasDnsName = false;

            Asn1OctetString extension = certificate.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (extension != null)
            {
                // A malformed extension names nothing, the common name included, as mbedTLS refuses the certificate.
                // Null for an empty one, which a peer may send: a null dereference is a kernel panic on Cosmos.
                GeneralName[] all;
                try
                {
                    all = GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(extension))?.GetNames();
                }
                catch
                {
                    return false;
                }

                if (all == null)
                {
                    return false;
                }

                foreach (GeneralName name in all)
                {
                    if (name.TagNo == GeneralName.DnsName)
                    {
                        hasDnsName = true;
                        if (address == null && MatchesDnsName(DerIA5String.GetInstance(name.Name).GetString(), host))
                        {
                            return true;
                        }
                    }
                    else if (name.TagNo == GeneralName.IPAddress && address != null)
                    {
                        if (SameBytes(Asn1OctetString.GetInstance(name.Name).GetOctets(), address))
                        {
                            return true;
                        }
                    }
                }
            }

            // The common name counts only for a certificate without DNS names (RFC 6125, 6.4.4).
            if (hasDnsName || address != null)
            {
                return false;
            }

            foreach (string commonName in certificate.SubjectDN.GetValueList(X509Name.CN))
            {
                if (MatchesDnsName(commonName, host))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// The four bytes of an IPv4 address literal, or null for a host name.
        /// </summary>
        /// <remarks>
        /// Parsed here, as Cosmos's IPAddress.TryParse throws and catches a FormatException within for a name of four
        /// labels (www.example.co.uk), on every handshake: an exception is slow on a Cosmos kernel, and two threads
        /// throwing at once halt it.
        /// </remarks>
        internal static byte[] ParseIPv4(string host)
        {
            byte[] address = new byte[4];
            int part = 0;
            int value = -1;

            for (int i = 0; i <= host.Length; i++)
            {
                char c = i < host.Length ? host[i] : '.';
                if (c >= '0' && c <= '9')
                {
                    value = (value < 0 ? 0 : value * 10) + (c - '0');
                    if (value > 255)
                    {
                        return null;
                    }
                }
                else if (c == '.' && value >= 0 && part < 4)
                {
                    address[part++] = (byte)value;
                    value = -1;
                }
                else
                {
                    return null;
                }
            }

            return part == 4 ? address : null;
        }

        /// <summary>
        /// Whether a certificate's DNS name matches a host: equal ignoring case, or a wildcard for its first label only.
        /// </summary>
        internal static bool MatchesDnsName(string pattern, string host)
        {
            pattern = pattern.TrimEnd('.');

            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                // "*.example.com" names "www.example.com", not "example.com" nor "a.b.example.com".
                int dot = host.IndexOf('.');
                if (dot <= 0)
                {
                    return false;
                }

                return string.Equals(pattern.Substring(1), host.Substring(dot), StringComparison.OrdinalIgnoreCase);
            }

            return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
        }

        private static string CheckValidity(BcCertificate certificate, DateTime now)
        {
            // The clock is in the message: a kernel's comes from the RTC, which may well be wrong.
            if (now < certificate.NotBefore)
            {
                return "The certificate of " + Name(certificate) + " isn't valid before " + certificate.NotBefore.ToString("u") + " (the clock says " + now.ToString("u") + ").";
            }

            if (now > certificate.NotAfter)
            {
                return "The certificate of " + Name(certificate) + " expired on " + certificate.NotAfter.ToString("u") + " (the clock says " + now.ToString("u") + ").";
            }

            return null;
        }

        // The extensions that may be critical: those the checks here honour, and the certificate policies, which
        // mbedTLS accepts too.
        private static readonly string[] s_handledExtensions =
        {
            X509Extensions.BasicConstraints.Id,
            X509Extensions.KeyUsage.Id,
            X509Extensions.ExtendedKeyUsage.Id,
            X509Extensions.SubjectAlternativeName.Id,
            X509Extensions.CertificatePolicies.Id,
        };

        private static string CheckCriticalExtensions(BcCertificate certificate)
        {
            ISet<string> critical = certificate.GetCriticalExtensionOids();
            if (critical == null)
            {
                return null;
            }

            foreach (string oid in critical)
            {
                if (Array.IndexOf(s_handledExtensions, oid) < 0)
                {
                    // nameConstraints (2.5.29.30), for one.
                    return "The certificate of " + Name(certificate) + " has a critical extension that isn't supported (" + oid + ").";
                }
            }

            return null;
        }

        private static bool AllowsPurpose(BcCertificate certificate, KeyPurposeID purpose)
        {
            IList<DerObjectIdentifier> purposes = certificate.GetExtendedKeyUsage();
            if (purposes == null)
            {
                return true;
            }

            foreach (DerObjectIdentifier allowed in purposes)
            {
                if (allowed.Equals(purpose) || allowed.Equals(KeyPurposeID.AnyExtendedKeyUsage))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// The certificate among <paramref name="candidates"/> (from <paramref name="first"/> on) that issued and signed
        /// <paramref name="certificate"/> and may sign certificates, or null.
        /// </summary>
        private static BcCertificate FindIssuer(BcCertificate certificate, IList<BcCertificate> candidates, int first, DateTime now, int authoritiesBelow, out string error)
        {
            error = null;

            for (int i = first; i < candidates.Count; i++)
            {
                BcCertificate candidate = candidates[i];
                if (!candidate.SubjectDN.Equivalent(certificate.IssuerDN) || !IsSignedBy(certificate, candidate))
                {
                    continue;
                }

                // A certificate authority's: basicConstraints cA, and keyCertSign when it has a key usage.
                bool[] keyUsage = candidate.GetKeyUsage();
                if (candidate.GetBasicConstraints() < 0 || (keyUsage != null && !keyUsage[KeyCertSign]))
                {
                    error = "The certificate of " + Name(certificate) + " was signed by " + Name(candidate) + ", which isn't a certificate authority.";
                    continue;
                }

                // Its basicConstraints' pathLenConstraint: how many certificate authorities may stand below it.
                if (candidate.GetBasicConstraints() < authoritiesBelow)
                {
                    error = "The certificate of " + Name(candidate) + " may not issue certificates through " + authoritiesBelow + " intermediate authorities.";
                    continue;
                }

                string validity = CheckValidity(candidate, now);
                if (validity != null)
                {
                    error = validity;
                    continue;
                }

                return candidate;
            }

            return null;
        }

        /// <summary>
        /// Whether BouncyCastle reads the certificate's public key without dereferencing null: an RSA, EC (on a named
        /// curve), Ed25519 or Ed448 one. It does for an EC key without its curve, or a DH, ElGamal or GOST key without
        /// parameters, which a peer may send: a kernel panic on Cosmos, which no catch stops. mbedTLS reads these
        /// kinds only, too.
        /// </summary>
        internal static bool HasReadableKey(BcCertificate certificate)
        {
            AlgorithmIdentifier algorithm = certificate.SubjectPublicKeyInfo?.Algorithm;
            if (algorithm == null)
            {
                return false;
            }

            DerObjectIdentifier oid = algorithm.Algorithm;
            if (oid.Equals(PkcsObjectIdentifiers.RsaEncryption) || oid.Equals(PkcsObjectIdentifiers.IdRsassaPss)
                || oid.Equals(EdECObjectIdentifiers.id_Ed25519) || oid.Equals(EdECObjectIdentifiers.id_Ed448))
            {
                return true;
            }

            // A named curve: an OID, as parsed, or as wrapped in X962Parameters in a certificate BouncyCastle made.
            return oid.Equals(X9ObjectIdentifiers.IdECPublicKey) && algorithm.Parameters?.ToAsn1Object() is DerObjectIdentifier;
        }

        private static bool IsSignedBy(BcCertificate certificate, BcCertificate issuer)
        {
            if (!HasReadableKey(issuer))
            {
                return false;
            }

            try
            {
                certificate.Verify(issuer.GetPublicKey());
                return true;
            }
            catch
            {
                // A different key, or a signature algorithm BouncyCastle doesn't know.
                return false;
            }
        }

        private static bool Contains(IList<BcCertificate> certificates, BcCertificate certificate)
        {
            // BouncyCastle compares the encodings, which it keeps.
            for (int i = 0; i < certificates.Count; i++)
            {
                if (certificates[i].Equals(certificate))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            return a.AsSpan().SequenceEqual(b);
        }

        private static string Name(BcCertificate certificate)
        {
            IList<string> commonNames = certificate.SubjectDN.GetValueList(X509Name.CN);
            return commonNames.Count > 0 ? commonNames[0] : certificate.SubjectDN.ToString();
        }
    }
}
