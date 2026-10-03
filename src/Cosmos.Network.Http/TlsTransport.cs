// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using X86 = System.Runtime.Intrinsics.X86;

namespace Cosmos.Network.Http;

/// <summary>
/// TLS 1.2 or 1.3 over a TCP connection, run by BouncyCastle in its
/// non-blocking mode: the protocol never touches the socket, it is handed
/// what arrives and asked for what to send, so the socket keeps being used
/// the way <see cref="SocketTransport"/> uses it.
/// </summary>
/// <remarks>
/// <para>
/// The client offers ECDHE key exchange only (X25519, P-256, P-384) with AEAD
/// ciphers, and AES-CBC for TLS 1.2 servers that have nothing better: no
/// RSA key exchange, no finite-field Diffie-Hellman, which is slow in managed
/// code. ChaCha20-Poly1305 comes first unless the CPU has AES instructions,
/// which BouncyCastle only uses on x86 and which a Cosmos kernel does not
/// enable: its AES runs from tables there.
/// </para>
/// <para>
/// A server may close the connection without sending close_notify first,
/// as many do: the response's framing (Content-Length or chunked) tells
/// whether it came whole, as for http://.
/// </para>
/// </remarks>
internal sealed class TlsTransport : ITransport
{
    private static TlsCrypto? s_crypto;

    private readonly SocketTransport _socket;
    private readonly HttpUrl _url;
    private readonly Client _client;
    private readonly TlsClientProtocol _protocol = new();
    private readonly byte[] _input = new byte[SocketTransport.ChunkSize];
    private readonly byte[] _output = new byte[SocketTransport.ChunkSize];

    public TlsTransport(SocketTransport socket, HttpUrl url, TrustedRoots roots, Func<ServerCertificate, bool>? validation)
    {
        _socket = socket;
        _url = url;
        _client = new Client(Crypto, url.Host, roots, validation);
    }

    public long LastActivity => _socket.LastActivity;

    /// <summary>
    /// The BouncyCastle crypto every connection shares: it holds the random
    /// generator, which seeds itself from <c>RandomNumberGenerator</c> once.
    /// </summary>
    private static TlsCrypto Crypto
    {
        get
        {
            TlsCrypto? crypto = Volatile.Read(ref s_crypto);
            if (crypto is null)
            {
                Interlocked.CompareExchange(ref s_crypto, new BcTlsCrypto(), null);
                crypto = Volatile.Read(ref s_crypto)!;
            }

            return crypto;
        }
    }

    /// <summary>Runs the handshake, which checks the server's certificate.</summary>
    /// <param name="timeout">How long the handshake may take, in milliseconds.</param>
    /// <exception cref="HttpException">The handshake failed, or the server's certificate is not trusted.</exception>
    public void Handshake(int timeout)
    {
        // BouncyCastle runs Miller-Rabin rounds on every RSA modulus it meets,
        // to refuse a prime one (whose private key anyone could work out): a
        // few modular exponentiations per key, a tenth of a second for a
        // 4096-bit root on a desktop and much more on a kernel. The keys here
        // are the roots' or certified by a CA, which checks them, and none
        // encrypts anything (there is no RSA key exchange), so this thread
        // skips the rounds for the handshake's length; the cheaper checks
        // (odd modulus, no small factor) still run.
        string? maxTests = Properties.GetThreadProperty(Properties.RsaMaxMRTests);
        Properties.SetThreadInt32(Properties.RsaMaxMRTests, 0);

        Exception? failure = null;
        try
        {
            RunHandshake(timeout);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        // Not in a finally: a Cosmos kernel skips them while an exception unwinds.
        if (maxTests is null)
        {
            Properties.RemoveThreadProperty(Properties.RsaMaxMRTests);
        }
        else
        {
            Properties.SetThreadProperty(Properties.RsaMaxMRTests, maxTests);
        }

        if (failure is not null)
        {
            throw Describe(failure);
        }
    }

    public void Send(byte[] data)
    {
        _protocol.WriteApplicationData(data, 0, data.Length);
        Flush();
    }

    public int Receive(byte[] buffer)
    {
        while (true)
        {
            int count = _protocol.ReadInput(buffer, 0, buffer.Length);
            if (count > 0)
            {
                return count;
            }

            // Everything received is taken, and the server sent close_notify,
            // or closed the connection and CloseInput below took that as one.
            if (_protocol.IsClosed)
            {
                return -1;
            }

            int read = _socket.Receive(_input);
            if (read == 0)
            {
                return 0;
            }

            Exception? failure = null;
            try
            {
                if (read > 0)
                {
                    _protocol.OfferInput(_input, 0, read);
                }
                else
                {
                    // Closed without close_notify: what was decrypted stands,
                    // and the framing tells whether the response is whole.
                    _protocol.CloseInput();
                }
            }
            catch (Exception exception)
            {
                failure = exception;
            }

            // Nothing the server waits for: our close_notify answering its
            // own, a warning, or the alert that tells it why we gave up. The
            // connection may be closing, and a Cosmos socket refuses to send
            // once the server has closed.
            TryFlush();

            if (failure is TlsFatalAlertReceived received)
            {
                throw new HttpException($"{_url.Authority} sent the {AlertDescription.GetText(received.AlertDescription)} alert.", received);
            }

            if (failure is EndOfStreamException)
            {
                throw new HttpException($"{_url.Authority} closed the connection in the middle of a TLS record: the response is cut short.", failure);
            }

            if (failure is not null)
            {
                throw new HttpException($"The TLS connection to {_url.Authority} failed: {failure.Message}", failure);
            }
        }
    }

    public void Close()
    {
        try
        {
            if (!_protocol.IsClosed)
            {
                _protocol.Close();
            }
        }
        catch (Exception)
        {
            // Closing a connection that failed has nothing to send.
        }

        // close_notify, or the alert that tells the server why the handshake failed.
        TryFlush();
        _socket.Close();
    }

    private void RunHandshake(int timeout)
    {
        long start = Stopwatch.GetTimestamp();
        _protocol.Connect(_client);
        Flush();

        while (_protocol.IsHandshaking)
        {
            // A whole deadline, not only a silence one: a server may keep
            // sending a byte now and then, or records that carry nothing.
            if (Stopwatch.GetElapsedTime(start).TotalMilliseconds > timeout)
            {
                throw new HttpException($"{_url.Authority} did not finish the TLS handshake in {timeout} ms.");
            }

            int read = _socket.Receive(_input);
            if (read > 0)
            {
                _protocol.OfferInput(_input, 0, read);
                Flush();
                continue;
            }

            if (read < 0)
            {
                throw new HttpException($"{_url.Authority} closed the connection during the TLS handshake.");
            }

        }

        if (!_protocol.IsConnected)
        {
            throw new HttpException($"{_url.Authority} closed the connection during the TLS handshake.");
        }
    }

    /// <summary>Sends what the protocol has to send.</summary>
    private void Flush()
    {
        int pending;
        while ((pending = _protocol.GetAvailableOutputBytes()) > 0)
        {
            int count = _protocol.ReadOutput(_output, 0, Math.Min(pending, _output.Length));
            _socket.Send(_output, count);
        }
    }

    private void TryFlush()
    {
        try
        {
            Flush();
        }
        catch (Exception)
        {
            // What could not be sent is lost, which leaves the response as it is.
        }
    }

    /// <summary>Turns a failed handshake into an exception that tells why.</summary>
    private HttpException Describe(Exception exception)
    {
        if (exception is HttpException http)
        {
            return http;
        }

        if (_client.ValidationFailure is Exception callback)
        {
            return new HttpException($"Checking the certificate of {_url.Host} failed: {callback.Message}", callback);
        }

        if (_client.CertificateError is string error)
        {
            return new HttpException($"The certificate of {_url.Host} is not trusted: {error}.", exception);
        }

        if (_client.ClosedDuringHandshake)
        {
            return new HttpException($"{_url.Authority} closed the connection during the TLS handshake.", exception);
        }

        string reason = exception switch
        {
            TlsFatalAlertReceived received => $"it sent the {AlertDescription.GetText(received.AlertDescription)} alert",
            TlsFatalAlert { AlertDescription: AlertDescription.protocol_version } => "it only speaks TLS versions older than 1.2",
            _ => exception.Message,
        };
        return new HttpException($"The TLS handshake with {_url.Authority} failed: {reason}", exception);
    }

    /// <summary>What the client offers, and how it checks the server.</summary>
    private sealed class Client : DefaultTlsClient
    {
        private static readonly int[] s_tls13Suites =
        [
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ];

        private static readonly int[] s_tls12AeadSuites =
        [
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];

        private static readonly int[] s_tls12CbcSuites =
        [
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        ];

        private readonly string _host;
        private readonly TrustedRoots _roots;
        private readonly Func<ServerCertificate, bool>? _validation;

        public Client(TlsCrypto crypto, string host, TrustedRoots roots, Func<ServerCertificate, bool>? validation)
            : base(crypto)
        {
            _host = host;
            _roots = roots;
            _validation = validation;
        }

        /// <summary>Why the server's certificate was refused, once it was.</summary>
        public string? CertificateError { get; private set; }

        /// <summary>What <see cref="HttpRequest.ServerCertificateValidation"/> threw, if it did.</summary>
        public Exception? ValidationFailure { get; private set; }

        /// <summary>Whether the server sent close_notify before the handshake was over: it gave up.</summary>
        public bool ClosedDuringHandshake { get; private set; }

        private bool _handshakeComplete;

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            _handshakeComplete = true;
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if (alertDescription == AlertDescription.close_notify && !_handshakeComplete)
            {
                ClosedDuringHandshake = true;
            }
        }

        public override TlsAuthentication GetAuthentication() => new Authentication(this);

        // Many servers close without close_notify; the response's framing
        // tells a cut-short response from a whole one.
        public override bool RequiresCloseNotify() => false;

        protected override int[] GetSupportedCipherSuites()
        {
            bool aesInstructions = X86.Aes.IsSupported && X86.Pclmulqdq.IsSupported;
            List<int> suites = new(s_tls13Suites.Length + s_tls12AeadSuites.Length + s_tls12CbcSuites.Length);
            AddPreferred(suites, s_tls13Suites, aesInstructions);
            AddPreferred(suites, s_tls12AeadSuites, aesInstructions);
            suites.AddRange(s_tls12CbcSuites);
            return TlsUtilities.GetSupportedCipherSuites(Crypto, suites.ToArray());
        }

        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles) =>
            new List<int> { NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1 };

        // No server name for an address: RFC 6066 forbids it.
        protected override IList<ServerName>? GetSniServerNames() => IPAddress.TryParse(_host, out _)
            ? null
            : new List<ServerName> { new(NameType.host_name, Encoding.ASCII.GetBytes(_host.TrimEnd('.'))) };

        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { ProtocolName.Http_1_1 };

        // No OCSP stapling: there is no revocation check to use it.
        protected override CertificateStatusRequest? GetCertificateStatusRequest() => null;

        /// <summary>
        /// Adds <paramref name="candidates"/> (AES-GCM ones, then ChaCha20
        /// ones) with ChaCha20 first unless the CPU has AES instructions.
        /// </summary>
        private static void AddPreferred(List<int> suites, int[] candidates, bool aesInstructions)
        {
            foreach (int suite in candidates)
            {
                if (IsChaCha(suite) != aesInstructions)
                {
                    suites.Add(suite);
                }
            }

            foreach (int suite in candidates)
            {
                if (IsChaCha(suite) == aesInstructions)
                {
                    suites.Add(suite);
                }
            }
        }

        private static bool IsChaCha(int suite) => suite
            is CipherSuite.TLS_CHACHA20_POLY1305_SHA256
            or CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            or CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;

        private void CheckServer(TlsServerCertificate serverCertificate)
        {
            TlsCertificate[] presented = serverCertificate.Certificate.GetCertificateList();
            if (presented.Length == 0)
            {
                CertificateError = "the server sent no certificate";
                throw new TlsFatalAlert(AlertDescription.bad_certificate, CertificateError);
            }

            List<byte[]> chain = new(presented.Length);
            List<X509Certificate> certificates = new(presented.Length);
            try
            {
                foreach (TlsCertificate certificate in presented)
                {
                    byte[] encoded = certificate.GetEncoded();
                    chain.Add(encoded);
                    certificates.Add(new X509Certificate(encoded));
                }
            }
            catch (Exception exception)
            {
                CertificateError = $"the certificates could not be read: {exception.Message}";
                throw new TlsFatalAlert(AlertDescription.bad_certificate, CertificateError);
            }

            string? error = CertificateValidator.Validate(certificates, _host, _roots, DateTime.UtcNow, out short alert);

            bool trusted = error is null;
            if (_validation is not null)
            {
                try
                {
                    trusted = _validation(new ServerCertificate(_host, chain, certificates[0], error));
                }
                catch (Exception exception)
                {
                    ValidationFailure = exception;
                    throw new TlsFatalAlert(AlertDescription.internal_error, exception.Message);
                }
            }

            if (!trusted)
            {
                CertificateError = error ?? "ServerCertificateValidation refused it";
                throw new TlsFatalAlert(error is null ? AlertDescription.bad_certificate : alert, CertificateError);
            }
        }

        private sealed class Authentication(Client client) : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) => client.CheckServer(serverCertificate);

            // No client certificate.
            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }
}
