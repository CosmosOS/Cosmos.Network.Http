// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.X509;

namespace Cosmos.Network.Http;

/// <summary>
/// The certificates an https:// server presented, and what the built-in check
/// made of them. <see cref="HttpRequest.ServerCertificateValidation"/>
/// receives one to decide whether to go on.
/// </summary>
public sealed class ServerCertificate
{
    private const string HexDigits = "0123456789ABCDEF";

    internal ServerCertificate(string host, IReadOnlyList<byte[]> chain, X509Certificate certificate, string? error)
    {
        Host = host;
        Chain = chain;
        Subject = certificate.SubjectDN.ToString();
        Issuer = certificate.IssuerDN.ToString();
        NotBefore = certificate.NotBefore;
        NotAfter = certificate.NotAfter;
        Fingerprint = Sha256Hex(chain[0]);
        Error = error;
    }

    /// <summary>The host the request connected to, as its URL names it.</summary>
    public string Host { get; }

    /// <summary>
    /// The certificates as the server sent them, DER-encoded: its own first,
    /// then whatever intermediates it chose to send.
    /// </summary>
    public IReadOnlyList<byte[]> Chain { get; }

    /// <summary>
    /// The distinguished name of the server's certificate, as BouncyCastle
    /// writes it: in the certificate's own order, without spaces, e.g.
    /// <c>C=US,O=Example Inc.,CN=example.com</c>.
    /// </summary>
    public string Subject { get; }

    /// <summary>The distinguished name of who issued the server's certificate, written as <see cref="Subject"/> is.</summary>
    public string Issuer { get; }

    /// <summary>When the server's certificate starts being valid, in UTC.</summary>
    public DateTime NotBefore { get; }

    /// <summary>When the server's certificate stops being valid, in UTC.</summary>
    public DateTime NotAfter { get; }

    /// <summary>
    /// The SHA-256 of the server's certificate, in uppercase hex without
    /// separators: what to compare to trust one certificate in particular,
    /// a self-signed one for instance. <c>openssl x509 -noout -fingerprint
    /// -sha256 -in cert.pem | tr -d :</c> prints the same, after
    /// <c>sha256 Fingerprint=</c>.
    /// </summary>
    public string Fingerprint { get; }

    /// <summary>
    /// Why the built-in check does not trust the server, or <see langword="null"/>
    /// when it does: the chain leads to one of Mozilla's roots, every
    /// certificate on it is valid now, and the server's certificate names
    /// <see cref="Host"/>.
    /// </summary>
    /// <remarks>
    /// It names the first problem found, and the dates are checked last: when
    /// a date is the problem, nothing else is wrong, so accepting such an
    /// error forgives a wrong clock and nothing more.
    /// </remarks>
    public string? Error { get; }

    private static string Sha256Hex(byte[] data)
    {
        Sha256Digest digest = new();
        digest.BlockUpdate(data, 0, data.Length);
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);

        char[] hex = new char[hash.Length * 2];
        for (int i = 0; i < hash.Length; i++)
        {
            hex[2 * i] = HexDigits[hash[i] >> 4];
            hex[(2 * i) + 1] = HexDigits[hash[i] & 0xF];
        }

        return new string(hex);
    }
}
