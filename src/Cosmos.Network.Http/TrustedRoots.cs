// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Cosmos.Network.Http;

/// <summary>
/// The root certificates a server's chain has to lead to, looked up by
/// subject. <see cref="Mozilla"/> holds the ones the package embeds.
/// </summary>
/// <remarks>
/// Each root is taken apart only as far as its subject until a chain names
/// it: a full certificate builds its public key, and BouncyCastle tests every
/// RSA modulus it meets, which a kernel takes its time over.
/// </remarks>
internal sealed class TrustedRoots
{
    private const string ResourceName = "Cosmos.Network.Http.cacert.pem";
    private const string BeginMarker = "-----BEGIN CERTIFICATE-----";
    private const string EndMarker = "-----END CERTIFICATE-----";

    private static TrustedRoots? s_mozilla;

    private readonly Dictionary<string, List<Root>> _bySubject = new(StringComparer.Ordinal);
    private readonly List<Root> _all = [];

    private TrustedRoots(IEnumerable<byte[]> certificates)
    {
        foreach (byte[] der in certificates)
        {
            Root root = new(X509CertificateStructure.GetInstance(der));
            string key = SubjectKey(root.Structure.Subject);
            if (!_bySubject.TryGetValue(key, out List<Root>? roots))
            {
                roots = [];
                _bySubject[key] = roots;
            }

            roots.Add(root);
            _all.Add(root);
        }
    }

    /// <summary>
    /// Mozilla's roots, as curl extracts them, read from the package the
    /// first time an https:// request needs them.
    /// </summary>
    public static TrustedRoots Mozilla
    {
        get
        {
            // Two threads may both load them the first time; one copy wins.
            // No lock: a lock is released in a finally, which a Cosmos kernel
            // skips while an exception unwinds.
            TrustedRoots? roots = Volatile.Read(ref s_mozilla);
            if (roots is null)
            {
                Interlocked.CompareExchange(ref s_mozilla, LoadEmbedded(), null);
                roots = Volatile.Read(ref s_mozilla)!;
            }

            return roots;
        }
    }

    /// <summary>How many roots there are.</summary>
    public int Count => _all.Count;

    /// <summary>Roots from PEM text: every <c>BEGIN CERTIFICATE</c> block in it, the rest ignored.</summary>
    /// <exception cref="FormatException">A block is not base64, or not a certificate.</exception>
    public static TrustedRoots FromPem(string pem) => new(ReadPem(pem));

    /// <summary>Roots from DER-encoded certificates.</summary>
    public static TrustedRoots FromCertificates(IEnumerable<byte[]> certificates) => new(certificates);

    /// <summary>
    /// The roots whose subject is <paramref name="name"/>: those encoded
    /// alike first, then any that only compare equal once normalized.
    /// </summary>
    public IEnumerable<X509Certificate> FindBySubject(X509Name name)
    {
        if (_bySubject.TryGetValue(SubjectKey(name), out List<Root>? roots))
        {
            foreach (Root root in roots)
            {
                yield return root.Certificate;
            }

            yield break;
        }

        foreach (Root root in _all)
        {
            if (root.Structure.Subject.Equivalent(name, true))
            {
                yield return root.Certificate;
            }
        }
    }

    private static string SubjectKey(X509Name name) => Convert.ToBase64String(name.GetEncoded());

    private static TrustedRoots LoadEmbedded()
    {
        Stream? stream = typeof(TrustedRoots).Assembly.GetManifestResourceStream(ResourceName);
        if (stream is null)
        {
            throw new InvalidOperationException($"The {ResourceName} resource is missing from the package.");
        }

        MemoryStream text = new();
        stream.CopyTo(text);
        stream.Dispose();
        return FromPem(Encoding.ASCII.GetString(text.GetBuffer(), 0, (int)text.Length));
    }

    private static List<byte[]> ReadPem(string pem)
    {
        List<byte[]> certificates = [];
        int position = 0;
        while (true)
        {
            int begin = pem.IndexOf(BeginMarker, position, StringComparison.Ordinal);
            if (begin < 0)
            {
                return certificates;
            }

            begin += BeginMarker.Length;
            int end = pem.IndexOf(EndMarker, begin, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new FormatException("A certificate in the PEM text has no END line.");
            }

            // Convert skips the line breaks and spaces between the base64 lines.
            certificates.Add(Convert.FromBase64String(pem.Substring(begin, end - begin)));
            position = end + EndMarker.Length;
        }
    }

    /// <summary>A root, kept as parsed structure until a chain needs its key.</summary>
    private sealed class Root(X509CertificateStructure structure)
    {
        private X509Certificate? _certificate;

        public X509CertificateStructure Structure { get; } = structure;

        /// <summary>The full certificate, built once: it caches its public key.</summary>
        public X509Certificate Certificate => _certificate ??= new X509Certificate(Structure);
    }
}
