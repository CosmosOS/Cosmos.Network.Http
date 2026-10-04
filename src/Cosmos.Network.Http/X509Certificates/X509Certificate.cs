//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

// nanoFramework's System.Net X509Certificate (nanoFramework.System.Net/X509Certificates/X509Certificate.cs).
// Cosmos: in the Cosmos.Network.Http namespace, as .NET's X509Certificate parses through OpenSSL, which a Cosmos
// kernel doesn't have; BouncyCastle parses here what mbedTLS parses natively on nanoFramework.

namespace Cosmos.Network.Http
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using Org.BouncyCastle.X509;

    /// <summary>
    /// Provides methods that help you use X.509 v.3 certificates.
    /// </summary>
    /// <remarks>
    /// Supported formats: DER and PEM.
    /// </remarks>
    public class X509Certificate
    {
        private readonly byte[] _certificate;

        /// <summary>
        /// Contains the certificate issuer.
        /// </summary>
        protected string _issuer;
        /// <summary>
        /// Contains the subject.
        /// </summary>
        protected string _subject;
        /// <summary>
        /// Contains the effective date of the certificate.
        /// </summary>
        protected DateTime _effectiveDate;
        /// <summary>
        /// Contains the expiration date of the certificate.
        /// </summary>
        protected DateTime _expirationDate;
        /// <summary>
        /// Contains the handle.
        /// </summary>
        protected byte[] _handle;
        /// <summary>
        /// Contains the session handle.
        /// </summary>
        protected byte[] _sessionHandle;

        /// <summary>
        /// Initializes a new instance of the X509Certificate class.
        /// </summary>
        public X509Certificate()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate"/> class defined from a sequence of bytes representing an X.509v3 certificate.
        /// </summary>
        /// <param name="certificate">A byte array containing data from an X.509 certificate.</param>
        /// <remarks>
        /// DER and PEM encoding are the supported formats. 
        /// </remarks>
        public X509Certificate(byte[] certificate)
        {
            _certificate = certificate;

            ParseCertificate(
                certificate,
                ref _issuer,
                ref _subject,
                ref _effectiveDate,
                ref _expirationDate);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate"/> class defined from a string with the content of an X.509v3 certificate.
        /// </summary>
        /// <param name="certificate">A string containing a X.509 certificate.</param>
        /// <remarks>
        /// Supported formats: DER and PEM.
        /// This methods is exclusive of .NET nanoFramework. The equivalent .NET constructor accepts a file name as the parameter.
        /// </remarks>
        public X509Certificate(string certificate)
        {
            var tempCertificate = Encoding.UTF8.GetBytes(certificate);

            //////////////////////////////////////////////
            // because this is parsing from a string    //
            // we need to keep the terminator           //
            //////////////////////////////////////////////
            _certificate = new byte[tempCertificate.Length + 1];
            Array.Copy(tempCertificate, _certificate, tempCertificate.Length);
            _certificate[_certificate.Length - 1] = 0;

            ParseCertificate(
                _certificate,
                ref _issuer,
                ref _subject,
                ref _effectiveDate,
                ref _expirationDate);
        }

        /// <summary>
        /// Gets the name of the certificate authority that issued the X.509v3 certificate.
        /// </summary>
        /// <value>
        /// The name of the certificate authority that issued the X.509v3 certificate.
        /// </value>
        public virtual string Issuer
        {
            get { return _issuer; }
        }

        /// <summary>
        /// Gets the subject distinguished name from the certificate.
        /// </summary>
        /// <value>
        /// The subject distinguished name from the certificate.
        /// </value>
        public virtual string Subject
        {
            get { return _subject; }
        }

        /// <summary>
        /// Returns the effective date of this X.509v3 certificate.
        /// </summary>
        /// <returns>The effective date for this X.509 certificate.</returns>
        /// <remarks>
        /// This methods is exclusive of nanoFramework. The equivalent .NET method is GetEffectiveDateString().
        /// </remarks>
        public virtual DateTime GetEffectiveDate()
        {
            return _effectiveDate;
        }

        /// <summary>
        /// Returns the expiration date of this X.509v3 certificate.
        /// </summary>
        /// <returns>The expiration date for this X.509 certificate.</returns>
        /// <remarks>
        /// This methods is exclusive of nanoFramework. The equivalent .NET method is GetExpirationDateString().
        /// </remarks>
        public virtual DateTime GetExpirationDate()
        {
            return _expirationDate;
        }

        /// <summary>
        /// Returns the raw data for the entire X.509v3 certificate as an array of bytes.
        /// </summary>
        /// <returns>A byte array containing the X.509 certificate data.</returns>
        public virtual byte[] GetRawCertData()
        {
            return _certificate;
        }

        // Cosmos: what nanoFramework parses natively. A PEM bundle is described by its first certificate.
        internal static void ParseCertificate(
            byte[] cert,
            ref string issuer,
            ref string subject,
            ref DateTime effectiveDate,
            ref DateTime expirationDate)
        {
            Org.BouncyCastle.X509.X509Certificate first = ParseCertificates(cert)[0];

            issuer = first.IssuerDN.ToString();
            subject = first.SubjectDN.ToString();
            effectiveDate = first.NotBefore;
            expirationDate = first.NotAfter;
        }

        /// <summary>
        /// Cosmos: every certificate of the raw data, for the TLS code: a PEM bundle holds several, as a CA bundle
        /// does on nanoFramework.
        /// </summary>
        internal Org.BouncyCastle.X509.X509Certificate[] GetCertificates()
        {
            if (_certificate == null)
            {
                throw new CryptographicException("The X509Certificate holds no certificate.");
            }

            return ParseCertificates(_certificate);
        }

        /// <summary>
        /// Cosmos: parses DER or PEM (one certificate or a bundle) with BouncyCastle.
        /// </summary>
        /// <exception cref="CryptographicException">No certificate could be read from <paramref name="data"/>.</exception>
        internal static Org.BouncyCastle.X509.X509Certificate[] ParseCertificates(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            int length = EncodedLength(data);

            byte[] input = new byte[length];
            Array.Copy(data, input, length);

            IList<Org.BouncyCastle.X509.X509Certificate> certificates;
            try
            {
                certificates = new X509CertificateParser().ReadCertificates(input);
            }
            catch (Exception e)
            {
                throw new CryptographicException("The certificate could not be parsed: " + e.Message, e);
            }

            if (certificates == null || certificates.Count == 0)
            {
                throw new CryptographicException("No X.509 certificate could be read, neither DER nor PEM.");
            }

            Org.BouncyCastle.X509.X509Certificate[] result = new Org.BouncyCastle.X509.X509Certificate[certificates.Count];
            certificates.CopyTo(result, 0);
            return result;
        }

        /// <summary>
        /// Cosmos: how many bytes of <paramref name="data"/> hold the DER or PEM, without the terminator nanoFramework
        /// ends what it gets as a string with, for mbedTLS. DER is measured by its length, as it may end with zeros.
        /// </summary>
        internal static int EncodedLength(byte[] data)
        {
            if (data.Length >= 2 && data[0] == 0x30)
            {
                // A DER SEQUENCE: its tag, its length (short or long form), its content.
                int lengthOctets = data[1] < 0x80 ? 0 : data[1] & 0x7F;
                if (lengthOctets <= 4 && data.Length >= 2 + lengthOctets)
                {
                    long contentLength = data[1] < 0x80 ? data[1] : 0;
                    for (int i = 0; i < lengthOctets; i++)
                    {
                        contentLength = (contentLength << 8) | data[2 + i];
                    }

                    long total = 2 + lengthOctets + contentLength;
                    if (total <= data.Length)
                    {
                        return (int)total;
                    }
                }

                return data.Length;
            }

            int length = data.Length;
            while (length > 0 && data[length - 1] == 0)
            {
                length--;
            }

            return length;
        }
    }
}

