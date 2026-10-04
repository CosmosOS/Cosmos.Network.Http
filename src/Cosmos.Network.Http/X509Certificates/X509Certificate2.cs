//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

// nanoFramework's System.Net X509Certificate2 (nanoFramework.System.Net/X509Certificates/X509Certificate2.cs).
// Cosmos: BouncyCastle decodes the private key, which mbedTLS decodes natively on nanoFramework, and the decoded key
// is kept for SslStream (a server certificate, or a client one).

using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Cosmos.Network.Http
{
    /// <summary>
    /// Represents an X.509 certificate.
    /// </summary>
    public class X509Certificate2 : X509Certificate
    {
#pragma warning disable S3459 // Unassigned members should be removed
        // field required to be accessible by native code
        private readonly byte[] _privateKey;
        private readonly string _password;

        // Cosmos: the decoded private key.
        private readonly AsymmetricKeyParameter _key;
#pragma warning restore S3459 // Unassigned members should be removed

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class.
        /// </summary>
        public X509Certificate2()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class using information from a byte array.
        /// </summary>
        /// <param name="rawData">A byte array containing data from an X.509 certificate.</param>
        public X509Certificate2(byte[] rawData)
            : base(rawData)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class using a string with the content of an X.509 certificate.
        /// </summary>
        /// <param name="certificate">A string containing a X.509 certificate.</param>
        /// <remarks>
        /// This methods is exclusive of .NET nanoFramework. The equivalent .NET constructor accepts a file name as the parameter.
        /// </remarks>
        public X509Certificate2(string certificate)
            : base(certificate)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class using a string with the content of an X.509 public certificate, the private key and a password used to access the private key.
        /// </summary>
        /// <param name="rawData">A string containing a X.509 certificate.</param>
        /// <param name="key">A string containing a private key in PEM or DER format.</param>
        /// <param name="password">The password required to decrypt the private key. Set to <see langword="null"/> if the <paramref name="rawData"/> or <paramref name="key"/> are not encrypted and do not require a password.</param>
        /// <remarks>
        /// This methods is exclusive of .NET nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public X509Certificate2(
            string rawData,
            string key,
            string password)
            : base(rawData)
        {
            var tempKey = Encoding.UTF8.GetBytes(key);

            //////////////////////////////////////////////
            // because this is parsing from a string    //
            // we need to keep the terminator           //
            //////////////////////////////////////////////
            var keyBuffer = new byte[tempKey.Length + 1];
            Array.Copy(tempKey, keyBuffer, tempKey.Length);
            keyBuffer[keyBuffer.Length - 1] = 0;

            _privateKey = keyBuffer;
            _password = password;

            _key = DecodePrivateKey(
                keyBuffer,
                password);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class using a string with the content of an X.509 public certificate, the private key and a password used to access the certificate.
        /// </summary>
        /// <param name="rawData">A byte array containing data from an X.509 certificate.</param>
        /// <param name="key">A string containing a private key in PEM or DER format.</param>
        /// <param name="password">The password required to decrypt the private key. Set to <see langword="null"/> if the <paramref name="rawData"/> or <paramref name="key"/> are not encrypted and do not require a password.</param>
        /// <remarks>
        /// This methods is exclusive of .NET nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public X509Certificate2(
            byte[] rawData,
            string key,
            string password)
            : base(rawData)
        {
            var tempKey = Encoding.UTF8.GetBytes(key);

            //////////////////////////////////////////////
            // because this is parsing from a string    //
            // we need to keep the terminator           //
            //////////////////////////////////////////////
            var keyBuffer = new byte[tempKey.Length + 1];
            Array.Copy(tempKey, keyBuffer, tempKey.Length);
            keyBuffer[keyBuffer.Length - 1] = 0;

            _privateKey = keyBuffer;
            _password = password;

            _key = DecodePrivateKey(
                keyBuffer,
                password);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="X509Certificate2"/> class using a string with the content of an X.509 public certificate, the private key and a password used to access the certificate.
        /// </summary>
        /// <param name="rawData">A byte array containing data from an X.509 certificate.</param>
        /// <param name="key">A byte array containing a PEM private key.</param>
        /// <param name="password">The password required to decrypt the private key. <see langword="null"/> if the <paramref name="rawData"/> or <paramref name="key"/> are not encrypted.</param>
        /// <remarks>
        /// This methods is exclusive of nanoFramework. There is no equivalent in .NET framework.
        /// </remarks>
        public X509Certificate2(
            byte[] rawData,
            byte[] key,
            string password)
            : base(rawData)
        {
            _privateKey = key;
            _password = password;

            _key = DecodePrivateKey(
                key,
                password);
        }

        /// <summary>
        /// Gets a value that indicates whether an <see cref="X509Certificate2"/> object contains a private key.
        /// </summary>
        /// <value><see langword="true"/> if the <see cref="X509Certificate2"/> object contains a private key; otherwise, <see langword="false"/>.</value>
        public bool HasPrivateKey
        {
            get
            {
                return (_privateKey != null);
            }
        }

        /// <summary>
        /// Gets the private key, null if there isn't a private key.
        /// </summary>
        /// <remarks>This will give you access directly to the raw decoded byte array of the private key</remarks>
        public byte[] PrivateKey => _privateKey;

        /// <summary>
        /// Gets the public key.
        /// </summary>
        /// <remarks>This will give you access directly to the raw decoded byte array of the public key.</remarks>
        public byte[] PublicKey => RawData;

        /// <summary>
        /// Gets the date (in UTC time) after which a certificate is no longer valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the expiration date for the certificate.</value>
        public DateTime NotAfter
        {
            get
            {
                return _expirationDate;
            }
        }

        /// <summary>
        /// Gets the date (in UTC time) on which a certificate becomes valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the effective date of the certificate.</value>
        public DateTime NotBefore
        {
            get
            {
                return _effectiveDate;
            }
        }

        /// <summary>
        /// Gets the raw data of a certificate.
        /// </summary>
        /// <value>The raw data of the certificate as a byte array.</value>
        public byte[] RawData
        {
            get
            {
                return base.GetRawCertData();
            }
        }

        /// <summary>
        /// Cosmos: the decoded private key, for SslStream.
        /// </summary>
        internal AsymmetricKeyParameter Key => _key;

        /// <summary>
        /// Cosmos: decodes what nanoFramework decodes natively (DecodePrivateKeyNative): PEM (PKCS#8, encrypted PKCS#8,
        /// PKCS#1 RSA, SEC1 EC, OpenSSL's encrypted PEM) or DER (PKCS#8, encrypted PKCS#8, PKCS#1 RSA, SEC1 EC).
        /// </summary>
        /// <exception cref="CryptographicException">No private key could be decoded from <paramref name="keyBuffer"/>.</exception>
        internal static AsymmetricKeyParameter DecodePrivateKey(
            byte[] keyBuffer,
            string password)
        {
            if (keyBuffer == null)
            {
                throw new ArgumentNullException(nameof(keyBuffer));
            }

            // Without the terminator nanoFramework adds to a key given as a string.
            int length = EncodedLength(keyBuffer);

            AsymmetricKeyParameter key = null;
            Exception error = null;
            try
            {
                if (length > 0 && keyBuffer[0] == 0x30)
                {
                    // A DER SEQUENCE.
                    byte[] der = new byte[length];
                    Array.Copy(keyBuffer, der, length);
                    key = DecodeDerPrivateKey(der, password);
                }
                else
                {
                    key = DecodePemPrivateKey(Encoding.UTF8.GetString(keyBuffer, 0, length), password);
                }
            }
            catch (Exception e)
            {
                error = e;
            }

            if (key == null)
            {
                throw new CryptographicException(error == null ? "No private key could be read, neither PEM nor DER." : "The private key could not be decoded: " + error.Message, error);
            }

            return key;
        }

        /// <summary>
        /// Cosmos: the PEM blocks read one by one, the keys decoded as DER (DecodeDerPrivateKey checks them first):
        /// BouncyCastle's OpenSSL reader builds an EC key without its curve, a null dereference (a kernel panic on Cosmos).
        /// It reads only OpenSSL's encrypted PEM (Proc-Type: 4,ENCRYPTED), which can be checked only once decrypted.
        /// </summary>
        private static AsymmetricKeyParameter DecodePemPrivateKey(string pem, string password)
        {
            var reader = new Org.BouncyCastle.Utilities.IO.Pem.PemReader(new StringReader(pem));

            Org.BouncyCastle.Utilities.IO.Pem.PemObject block;
            while ((block = reader.ReadPemObject()) != null)
            {
                bool legacyEncrypted = false;
                foreach (Org.BouncyCastle.Utilities.IO.Pem.PemHeader header in block.Headers)
                {
                    legacyEncrypted |= header.Name == "Proc-Type" && header.Value.IndexOf("ENCRYPTED", StringComparison.Ordinal) >= 0;
                }

                switch (block.Type)
                {
                    case "PRIVATE KEY":
                    case "RSA PRIVATE KEY":
                    case "EC PRIVATE KEY":
                    case "ENCRYPTED PRIVATE KEY":
                        if (!legacyEncrypted)
                        {
                            return DecodeDerPrivateKey(block.Content, block.Type == "ENCRYPTED PRIVATE KEY" ? password ?? "" : null);
                        }

                        return DecodeLegacyEncryptedPem(pem, password);
                }
            }

            return null;
        }

        private static AsymmetricKeyParameter DecodeLegacyEncryptedPem(string pem, string password)
        {
            PemReader reader = new PemReader(new StringReader(pem), password == null ? null : new PasswordFinder(password));

            object pemObject;
            while ((pemObject = reader.ReadObject()) != null)
            {
                if (pemObject is AsymmetricCipherKeyPair pair)
                {
                    return pair.Private;
                }

                if (pemObject is AsymmetricKeyParameter parameter && parameter.IsPrivate)
                {
                    return parameter;
                }
            }

            return null;
        }

        private static AsymmetricKeyParameter DecodeDerPrivateKey(byte[] der, string password)
        {
            Asn1Sequence sequence = Asn1Sequence.GetInstance(der);

            if (password != null && sequence.Count == 2)
            {
                // EncryptedPrivateKeyInfo: algorithm, encrypted data.
                // Cosmos: decrypted first, so the key is checked before BouncyCastle builds it (CreateKey).
                return CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), EncryptedPrivateKeyInfo.GetInstance(sequence)));
            }

            if (sequence.Count == 9)
            {
                // PKCS#1 RSAPrivateKey: version, n, e, d, p, q, dP, dQ, qInv.
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(sequence);
                return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);
            }

            if (sequence.Count >= 2 && sequence[1] is Asn1OctetString)
            {
                // SEC1 ECPrivateKey: version, private key, [0] parameters, [1] public key.
                ECPrivateKeyStructure ec = ECPrivateKeyStructure.GetInstance(sequence);
                AlgorithmIdentifier algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, ec.Parameters);
                return CreateKey(new PrivateKeyInfo(algorithm, ec.ToAsn1Object()));
            }

            // PKCS#8 PrivateKeyInfo.
            return CreateKey(PrivateKeyInfo.GetInstance(sequence));
        }

        /// <summary>
        /// Cosmos: BouncyCastle's CreateKey for the kinds of keys it builds without dereferencing null: RSA, EC with its
        /// curve, Ed25519 and Ed448 (those a TLS signer takes). It does for an EC key without its curve, or a DH,
        /// ElGamal or GOST key without parameters: a kernel panic on Cosmos, where this throws.
        /// </summary>
        private static AsymmetricKeyParameter CreateKey(PrivateKeyInfo info)
        {
            AlgorithmIdentifier algorithm = info.PrivateKeyAlgorithm;
            DerObjectIdentifier oid = algorithm.Algorithm;

            bool supported = oid.Equals(PkcsObjectIdentifiers.RsaEncryption) || oid.Equals(PkcsObjectIdentifiers.IdRsassaPss)
                || oid.Equals(Org.BouncyCastle.Asn1.EdEC.EdECObjectIdentifiers.id_Ed25519) || oid.Equals(Org.BouncyCastle.Asn1.EdEC.EdECObjectIdentifiers.id_Ed448)
                || (oid.Equals(X9ObjectIdentifiers.IdECPublicKey) && algorithm.Parameters != null && !(algorithm.Parameters is Asn1Null));

            if (!supported)
            {
                throw new CryptographicException("A private key of this kind isn't supported (" + oid.Id + "), or an EC one lacks its curve.");
            }

            return PrivateKeyFactory.CreateKey(info);
        }

        private sealed class PasswordFinder : IPasswordFinder
        {
            private readonly string _password;

            internal PasswordFinder(string password)
            {
                _password = password;
            }

            public char[] GetPassword()
            {
                return _password.ToCharArray();
            }
        }
    }
}
