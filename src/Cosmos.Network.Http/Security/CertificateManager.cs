//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

// nanoFramework's System.Net CertificateManager (nanoFramework.System.Net/Security/CertificateManager.cs). Cosmos: a
// kernel has no device certificate store, so the store is in memory and starts with the Mozilla roots the package
// embeds (resources/cacert.pem): an https:// server is checked against them unless a CA certificate is given, or a
// bundle added here replaces them, as one replaces the device's bundle on nanoFramework.

using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace Cosmos.Network.Http
{
    /// <summary>
    /// Provides an interface to the device certificate store to manage <see cref="X509Certificate"/>.
    /// </summary>
    /// <remarks>
    /// Cosmos: the store starts with the Mozilla root certificates, as curl extracts them.
    /// </remarks>
    public static class CertificateManager
    {
        private const string RootsResource = "Cosmos.Network.Http.cacert.pem";

        // The bundle added, which replaces the embedded roots once s_added is 1, and those roots, parsed on first use.
        // Each replaced whole, never changed in place, so a handshake on another thread reads a complete one without a
        // lock; two fields, so the roots parsed on one thread can't replace a bundle another adds meanwhile. An int and
        // Interlocked for s_added, as Interlocked on references isn't atomic on a Cosmos kernel.
        private static volatile Org.BouncyCastle.X509.X509Certificate[] s_bundle;
        private static volatile Org.BouncyCastle.X509.X509Certificate[] s_roots;
        private static int s_added;

        /// <summary>
        /// Adds a Certificate Authority Root bundle <see cref="X509Certificate"/> to the store.
        /// If there is already a CA Root bundle it will be replaced with this one.
        /// </summary>
        /// <param name="ca">The Certificate Authority certificate bundle to be added store.</param>
        /// <returns>
        /// True if the certificate bundle was correctly added to the device certificate store.
        /// </returns>
        /// <remarks>
        /// This method is exclusive of nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public static bool AddCaCertificateBundle(X509Certificate[] ca)
        {
            // Cosmos: each certificate's own parse, where nanoFramework concatenates their PEM text for mbedTLS (which
            // loses a byte of a DER one).
            if (ca == null)
            {
                return false;
            }

            List<Org.BouncyCastle.X509.X509Certificate> bundle = new List<Org.BouncyCastle.X509.X509Certificate>();
            try
            {
                foreach (X509Certificate cert in ca)
                {
                    bundle.AddRange(cert.GetCertificates());
                }
            }
            catch
            {
                return false;
            }

            s_bundle = bundle.ToArray();
            Interlocked.Exchange(ref s_added, 1);
            return true;
        }

        /// <summary>
        /// Adds a Certificate Authority Root bundle <see cref="X509Certificate"/> to the store.
        /// If there is already a CA Root bundle it will be replaced with this one.
        /// </summary>
        /// <param name="ca">The Certificate Authority certificate bundle to be added store.</param>
        /// <returns>
        /// True if the certificate bundle was correctly added to the device certificate store.
        /// </returns>
        /// <remarks>
        /// This method is exclusive of nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public static bool AddCaCertificateBundle(string ca)
        {
            return AddCaCertificateBundle(Encoding.UTF8.GetBytes(ca));
        }

        /// <summary>
        /// Adds a Certificate Authority Root bundle <see cref="X509Certificate"/> to the store.
        /// If there is already a CA Root bundle it will be replaced with this one.
        /// </summary>
        /// <param name="ca">The Certificate Authority certificate bundle to be added store.</param>
        /// <returns>
        /// True if the certificate bundle was correctly added to the device certificate store.
        /// </returns>
        /// <remarks>
        /// This method is exclusive of nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public static bool AddCaCertificateBundle(byte[] ca)
        {
            // Cosmos: what nanoFramework stores natively.
            if (ca == null)
            {
                return false;
            }

            Org.BouncyCastle.X509.X509Certificate[] bundle;
            try
            {
                bundle = X509Certificate.ParseCertificates(ca);
            }
            catch
            {
                return false;
            }

            s_bundle = bundle;
            Interlocked.Exchange(ref s_added, 1);
            return true;
        }

        /// <summary>
        /// Cosmos: the store's certificates, which a TLS client given no CA certificate trusts.
        /// </summary>
        internal static Org.BouncyCastle.X509.X509Certificate[] GetTrustedCertificates()
        {
            // Parsed on first use: about 150 roots. Two threads may both parse them; either result will do.
            if (Volatile.Read(ref s_added) != 0)
            {
                return s_bundle;
            }

            Org.BouncyCastle.X509.X509Certificate[] roots = s_roots;
            if (roots == null)
            {
                roots = LoadEmbeddedRoots();
                s_roots = roots;
            }

            // Unless a bundle was added meanwhile, which wins.
            return Volatile.Read(ref s_added) != 0 ? s_bundle : roots;
        }

        private static Org.BouncyCastle.X509.X509Certificate[] LoadEmbeddedRoots()
        {
            Stream stream = typeof(CertificateManager).Assembly.GetManifestResourceStream(RootsResource);
            if (stream == null)
            {
                throw new InvalidOperationException("The embedded root certificates (" + RootsResource + ") are missing.");
            }

            byte[] pem = new byte[stream.Length];
            int read = 0;
            while (read < pem.Length)
            {
                int count = stream.Read(pem, read, pem.Length - read);
                if (count <= 0)
                {
                    break;
                }

                read += count;
            }

            stream.Dispose();

            return X509Certificate.ParseCertificates(pem);
        }
    }
}
