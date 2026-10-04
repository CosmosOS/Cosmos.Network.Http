// Cosmos: nanoFramework's SslNative (the externs at the end of nanoFramework.System.Net/Security/NetworkSecurity.cs)
// is native code over mbedTLS. This is its managed counterpart over BouncyCastle's TLS 1.2 and 1.3, which runs on a
// Cosmos kernel: its SecureRandom draws from .NET's RandomNumberGenerator, which Cosmos plugs with a kernel CSPRNG.
// One instance is one SSL context and its session; SslStream holds it where nanoFramework holds a context handle.
// BouncyCastle runs non-blocking here: what the socket holds is offered to it and what it produces is sent, so every
// wait is NetworkStream's (Cosmos's sockets don't wait themselves).

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Cosmos.Network.Http
{
    /// <summary>
    /// The TLS context and session of an <see cref="SslStream"/>.
    /// </summary>
    internal sealed class SslNative
    {
        // How long a handshake waits for the peer when the stream has no read timeout: a native socket waits as long as
        // mbedTLS lets it, which would hang a kernel on a peer that never answers.
        private const int DefaultHandshakeTimeout = 30_000;

        // A TLS record: 16 KiB of data, plus the header and what encryption adds.
        private const int ReceiveBufferSize = 17 * 1024;

        // The key exchange groups: elliptic curves only, as finite-field Diffie-Hellman is slow in managed code.
        private static readonly int[] Groups = { NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1 };

        // Cosmos: AES runs from tables without AES-NI and PCLMULQDQ (a Cosmos kernel enables neither), where
        // ChaCha20-Poly1305 is fast, so a client without them offers ChaCha20 first.
        private static readonly int[] ClientCipherSuites = System.Runtime.Intrinsics.X86.Aes.IsSupported && System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported
            ? new int[]
            {
                CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            }
            : new int[]
            {
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            };

        // A server's: TLS 1.3, and TLS 1.2's ephemeral elliptic-curve AEAD suites for its key's kind.
        private static readonly int[] ServerCipherSuitesRsa =
        {
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        };

        private static readonly int[] ServerCipherSuitesEcdsa =
        {
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        };

        private readonly bool _isServer;
        private readonly SslProtocols _protocols;
        private readonly SslVerification _verification;
        private readonly X509Certificate _certificate;
        private readonly AsymmetricKeyParameter _key;
        private readonly Org.BouncyCastle.X509.X509Certificate[] _trusted;
        private readonly BcTlsCrypto _crypto;

        private TlsProtocol _protocol;
        private NetworkStream _transport;
        private byte[] _receiveBuffer;
        private bool _inputClosed;

        private SslNative(bool isServer, SslProtocols protocols, SslVerification verification, X509Certificate certificate, X509Certificate ca)
        {
            if (protocols != SslProtocols.None && (protocols & (SslProtocols.Tls12 | SslProtocols.Tls13)) == 0)
            {
                throw new NotSupportedException("Only TLS 1.2 and TLS 1.3 are supported, which " + protocols + " doesn't include.");
            }

            _isServer = isServer;
            _protocols = protocols;
            _verification = verification;
            _certificate = certificate;

            if (certificate != null)
            {
                _key = (certificate as X509Certificate2)?.Key;
                if (_key == null)
                {
                    throw new AuthenticationException("The " + (isServer ? "server" : "client") + " certificate has no private key: give an X509Certificate2 made with its key.");
                }

                // Parsed now, so a certificate that doesn't parse fails here rather than in the handshake.
                certificate.GetCertificates();
            }

            // The CA given to the stream, else the CertificateManager's, as nanoFramework falls back on the device's store.
            _trusted = ca != null ? ca.GetCertificates() : null;

            _crypto = new BcTlsCrypto(new SecureRandom());
        }

        /// <summary>
        /// Creates a server context (nanoFramework: SecureServerInit).
        /// </summary>
        /// <remarks>
        /// <paramref name="useDeviceCertificate"/>: a Cosmos kernel has no device certificate store.
        /// </remarks>
        internal static SslNative SecureServerInit(
            SslProtocols sslProtocols,
            SslVerification sslCertVerify,
            X509Certificate certificate,
            X509Certificate ca,
            bool useDeviceCertificate)
        {
            if (certificate == null)
            {
                throw new AuthenticationException("A TLS server needs a certificate.");
            }

            return new SslNative(true, sslProtocols, sslCertVerify, certificate, ca);
        }

        /// <summary>
        /// Creates a client context (nanoFramework: SecureClientInit).
        /// </summary>
        /// <remarks>
        /// <paramref name="useDeviceCertificate"/>: a Cosmos kernel has no device certificate store.
        /// </remarks>
        internal static SslNative SecureClientInit(
            SslProtocols sslProtocols,
            SslVerification sslCertVerify,
            X509Certificate certificate,
            X509Certificate ca,
            bool useDeviceCertificate)
        {
            return new SslNative(false, sslProtocols, sslCertVerify, certificate, ca);
        }

        /// <summary>
        /// Runs the handshake as the server (nanoFramework: SecureAccept).
        /// </summary>
        internal void SecureAccept(NetworkStream transport)
        {
            _transport = transport;

            TlsServerProtocol protocol = new TlsServerProtocol();
            _protocol = protocol;

            try
            {
                protocol.Accept(new Server(this));
            }
            catch (Exception e)
            {
                throw Failure(null, e);
            }

            Handshake(null, transport.ReadTimeout);
        }

        /// <summary>
        /// Starts the handshake as the server without waiting for the client: <see cref="AdvanceHandshake"/> goes on
        /// with it as its messages arrive. Cosmos: for HttpListener, whose one thread serves every connection.
        /// </summary>
        internal void BeginAccept(NetworkStream transport)
        {
            _transport = transport;

            TlsServerProtocol protocol = new TlsServerProtocol();
            _protocol = protocol;

            try
            {
                protocol.Accept(new Server(this));
            }
            catch (Exception e)
            {
                throw Failure(null, e);
            }
        }

        /// <summary>
        /// Goes on with a handshake <see cref="BeginAccept"/> started, with what has arrived, without waiting.
        /// </summary>
        /// <returns>Whether the handshake is complete.</returns>
        internal bool AdvanceHandshake()
        {
            // As in Handshake.
            Properties.SetThreadInt32(Properties.RsaMaxMRTests, 0);

            bool complete = false;
            Exception error = null;
            try
            {
                complete = StepHandshake();
            }
            catch (Exception e)
            {
                error = e;
            }

            Properties.RemoveThreadProperty(Properties.RsaMaxMRTests);

            if (error != null)
            {
                throw error;
            }

            return complete;
        }

        private bool StepHandshake()
        {
            Socket socket = _transport._socket;

            while (!_protocol.IsConnected)
            {
                if (_protocol.IsClosed)
                {
                    throw new AuthenticationException(Describe(null) + " failed: the TLS session was closed.");
                }

                SendOutput();

                int available = socket.Available;
                if (available == 0)
                {
                    // Read before Poll, as in NetworkStream.WaitForData.
                    bool connected = socket.Connected;
                    if (socket.Poll(0, SelectMode.SelectRead))
                    {
                        if (socket.Available > 0)
                        {
                            continue;
                        }

                        throw new AuthenticationException(Describe(null) + " failed: the peer closed the connection.");
                    }

                    if (!connected)
                    {
                        throw new IOException("The connection was closed.");
                    }

                    return false;
                }

                int read = ReceiveAvailable(socket, available);
                try
                {
                    _protocol.OfferInput(ReceiveBuffer, 0, read);
                }
                catch (Exception e)
                {
                    // The alert BouncyCastle queued tells the peer why.
                    SendOutputQuietly();
                    throw Failure(null, e);
                }
            }

            // The client's Finished in TLS 1.3, the server's in a resumed TLS 1.2 handshake.
            SendOutput();
            return true;
        }

        /// <summary>
        /// Runs the handshake as the client (nanoFramework: SecureConnect).
        /// </summary>
        internal void SecureConnect(string targetHost, NetworkStream transport)
        {
            _transport = transport;

            TlsClientProtocol protocol = new TlsClientProtocol();
            _protocol = protocol;

            try
            {
                protocol.Connect(new Client(this, targetHost));
            }
            catch (Exception e)
            {
                throw Failure(targetHost, e);
            }

            Handshake(targetHost, transport.ReadTimeout);
        }

        /// <summary>
        /// Reads decrypted data, waiting up to <paramref name="timeout_ms"/> for some (nanoFramework: SecureRead).
        /// </summary>
        /// <returns>The number of bytes read, 0 once the peer has closed the session or the connection.</returns>
        internal int SecureRead(byte[] buffer, int offset, int size, int timeout_ms)
        {
            while (_protocol.ApplicationDataAvailable == 0)
            {
                if (_protocol.IsClosed || _inputClosed)
                {
                    return 0;
                }

                int read = Receive(timeout_ms);
                if (read == 0)
                {
                    // Closed without a close_notify alert: the end of the data, as the HTTP code knows its length.
                    _inputClosed = true;
                    return 0;
                }

                Offer(read);
            }

            return _protocol.ReadInput(buffer, offset, size);
        }

        /// <summary>
        /// Encrypts and sends data (nanoFramework: SecureWrite).
        /// </summary>
        /// <returns>The number of bytes written.</returns>
        internal int SecureWrite(byte[] buffer, int offset, int size, int timeout_ms)
        {
            try
            {
                _protocol.WriteApplicationData(buffer, offset, size);
            }
            catch (Exception e)
            {
                SendOutputQuietly();
                throw new IOException("TLS: " + e.Message, e);
            }

            SendOutput();
            return size;
        }

        /// <summary>
        /// The number of decrypted bytes that can be read without waiting (nanoFramework: DataAvailable).
        /// </summary>
        internal int DataAvailable()
        {
            // What has arrived is decrypted first: nanoFramework's native layer does it as data comes in.
            Socket socket = _transport._socket;

            int available;
            while (!_protocol.IsClosed && !_inputClosed && (available = socket.Available) > 0)
            {
                int read = ReceiveAvailable(socket, available);
                if (read <= 0)
                {
                    break;
                }

                Offer(read);
            }

            return _protocol.ApplicationDataAvailable;
        }

        /// <summary>
        /// Sends the close_notify alert and closes the socket (nanoFramework: SecureCloseSocket).
        /// </summary>
        internal void SecureCloseSocket()
        {
            if (_transport == null)
            {
                return;
            }

            try
            {
                // Not to a peer that has closed the connection: Cosmos's Send would throw.
                if (_protocol != null && !_protocol.IsClosed && _transport._socket.Connected)
                {
                    _protocol.Close();
                    SendOutput();
                }
            }
            catch
            {
                // The peer may be gone already; the socket is closed all the same.
            }

            CloseSocket(_transport._socket);
        }

        /// <summary>
        /// Releases the context (nanoFramework: ExitSecureContext).
        /// </summary>
        internal void ExitSecureContext()
        {
            // Nothing to free: the stream drops this context, and the garbage collector takes it. Its fields stay set,
            // so a read or write on another thread meanwhile fails on the closed socket, with an exception, rather
            // than on null (a kernel panic on Cosmos).
        }

        /// <summary>
        /// Closes a socket, which may have been closed already.
        /// </summary>
        internal static void CloseSocket(Socket socket)
        {
            try
            {
                socket.Close();
            }
            catch
            {
                // Closed already.
            }
        }

        private byte[] ReceiveBuffer => _receiveBuffer ??= new byte[ReceiveBufferSize];

        private void Handshake(string peer, int timeout)
        {
            if (timeout == Timeout.Infinite)
            {
                timeout = DefaultHandshakeTimeout;
            }

            // BouncyCastle tests every RSA modulus it meets for primality (Miller-Rabin), certificates' included,
            // which is slow in managed code and checks nothing a signature check needs. Restored on both paths below,
            // not in a finally: a Cosmos kernel skips them while an exception unwinds.
            Properties.SetThreadInt32(Properties.RsaMaxMRTests, 0);

            Exception error = null;
            try
            {
                RunHandshake(peer, timeout);
            }
            catch (Exception e)
            {
                error = e;
            }

            Properties.RemoveThreadProperty(Properties.RsaMaxMRTests);

            if (error != null)
            {
                throw error;
            }
        }

        private void RunHandshake(string peer, int timeout)
        {
            // The whole handshake within the timeout, which a peer trickling its messages would otherwise stretch:
            // a server handshakes on the thread serving every connection.
            long start = Stopwatch.GetTimestamp();

            while (!_protocol.IsConnected)
            {
                if (_protocol.IsClosed)
                {
                    throw new AuthenticationException(Describe(peer) + " failed: the TLS session was closed.");
                }

                SendOutput();

                int left = timeout - (int)Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                if (left <= 0)
                {
                    throw new IOException(Describe(peer) + " took longer than " + timeout + " ms.", new SocketException((int)SocketError.TimedOut));
                }

                int read = Receive(left);
                if (read == 0)
                {
                    throw new AuthenticationException(Describe(peer) + " failed: the peer closed the connection.");
                }

                try
                {
                    _protocol.OfferInput(ReceiveBuffer, 0, read);
                }
                catch (Exception e)
                {
                    // The alert BouncyCastle queued tells the peer why.
                    SendOutputQuietly();
                    throw Failure(peer, e);
                }
            }

            // The client's Finished in TLS 1.3, the server's in a resumed TLS 1.2 handshake.
            SendOutput();
        }

        private int Receive(int timeout)
        {
            int available = _transport.WaitForData(timeout);
            if (available == 0)
            {
                return 0;
            }

            return ReceiveAvailable(_transport._socket, available);
        }

        private int ReceiveAvailable(Socket socket, int available)
        {
            try
            {
                return socket.Receive(ReceiveBuffer, 0, Math.Min(available, ReceiveBufferSize), SocketFlags.None);
            }
            catch (Exception e)
            {
                // Cosmos's Receive throws InvalidOperationException for a socket closed meanwhile.
                throw new IOException("Receiving failed: " + e.Message, e);
            }
        }

        private void Offer(int count)
        {
            try
            {
                _protocol.OfferInput(ReceiveBuffer, 0, count);
            }
            catch (Exception e)
            {
                SendOutputQuietly();
                throw new IOException("TLS: " + e.Message, e);
            }

            // An alert, a key update or the answer to a close_notify. That answer is a courtesy, to a peer that may
            // have closed the connection already (Cosmos's Send then throws), and what came with its close_notify is
            // still to be read.
            if (_protocol.IsClosed)
            {
                SendOutputQuietly();
            }
            else
            {
                SendOutput();
            }
        }

        private void SendOutput()
        {
            int count = _protocol.GetAvailableOutputBytes();
            if (count == 0)
            {
                return;
            }

            byte[] output = new byte[count];
            count = _protocol.ReadOutput(output, 0, count);

            Socket socket = _transport._socket;
            int sent = 0;
            while (sent < count)
            {
                int bytes;
                try
                {
                    bytes = socket.Send(output, sent, count - sent, SocketFlags.None);
                }
                catch (Exception e)
                {
                    // Cosmos's Send throws a plain Exception once the peer has closed the connection.
                    throw new IOException("Sending failed: " + e.Message, e);
                }

                if (bytes <= 0)
                {
                    throw new IOException("The connection was closed while sending.");
                }

                sent += bytes;
            }
        }

        private void SendOutputQuietly()
        {
            try
            {
                SendOutput();
            }
            catch
            {
                // The handshake has failed already; the alert is a courtesy.
            }
        }

        private static string Describe(string peer)
        {
            return string.IsNullOrEmpty(peer) ? "The TLS handshake" : "The TLS handshake with " + peer;
        }

        private static AuthenticationException Failure(string peer, Exception e)
        {
            // BouncyCastle wraps what fails in a callback (the certificate check, for one) in an internal_error alert:
            // the innermost exception says why.
            string reason = e.Message;
            for (Exception inner = e.InnerException; inner != null; inner = inner.InnerException)
            {
                if (!string.IsNullOrEmpty(inner.Message))
                {
                    reason = inner.Message;
                }
            }

            return new AuthenticationException(Describe(peer) + " failed: " + reason, e);
        }

        private ProtocolVersion[] SupportedVersions(ProtocolVersion[] defaults)
        {
            // SslProtocols.None lets BouncyCastle choose (TLS 1.3 and 1.2), as it lets the system choose in .NET.
            if (_protocols == SslProtocols.None)
            {
                return defaults;
            }

            List<ProtocolVersion> versions = new List<ProtocolVersion>();
            if ((_protocols & SslProtocols.Tls13) != 0)
            {
                versions.Add(ProtocolVersion.TLSv13);
            }

            if ((_protocols & SslProtocols.Tls12) != 0)
            {
                versions.Add(ProtocolVersion.TLSv12);
            }

            return versions.ToArray();
        }

        /// <summary>
        /// Checks the certificate the peer sent, as mbedTLS's verify mode does.
        /// </summary>
        /// <param name="chain">The peer's certificate chain, leaf first.</param>
        /// <param name="host">The host the certificate must name, or null for a client certificate.</param>
        private void VerifyPeer(Certificate chain, string host)
        {
            // Cosmos: certificates whose key BouncyCastle would dereference null on are refused first, verification
            // or not: it reads the peer's key after this, and the verifier its issuers' (CertificateVerifier.HasReadableKey).
            for (int i = 0; chain != null && i < chain.Length; i++)
            {
                var certificate = new Org.BouncyCastle.X509.X509Certificate(chain.GetCertificateAt(i).GetEncoded());
                if (!CertificateVerifier.HasReadableKey(certificate))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_certificate, "The certificate of " + certificate.SubjectDN + " has a key of a kind that isn't supported.");
                }
            }

            if (_verification == SslVerification.NoVerification)
            {
                return;
            }

            if (chain == null || chain.IsEmpty)
            {
                // A server that only asked (VerifyPeer) goes on without one.
                if (_isServer && _verification == SslVerification.VerifyPeer)
                {
                    return;
                }

                throw new TlsFatalAlert(_isServer ? AlertDescription.certificate_required : AlertDescription.bad_certificate, "The peer sent no certificate.");
            }

            Org.BouncyCastle.X509.X509Certificate[] certificates = new Org.BouncyCastle.X509.X509Certificate[chain.Length];
            for (int i = 0; i < certificates.Length; i++)
            {
                certificates[i] = new Org.BouncyCastle.X509.X509Certificate(chain.GetCertificateAt(i).GetEncoded());
            }

            string error = CertificateVerifier.Verify(certificates, host, _trusted ?? CertificateManager.GetTrustedCertificates(), DateTime.UtcNow);
            if (error != null)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, error);
            }
        }

        /// <summary>
        /// The signer for this side's certificate, or null when there is none or no signature algorithm of the peer fits its key.
        /// </summary>
        private TlsCredentialedSigner Credentials(TlsContext context, IList<SignatureAndHashAlgorithm> peerAlgorithms)
        {
            if (_key == null)
            {
                return null;
            }

            bool tls13 = TlsUtilities.IsTlsV13(context);

            SignatureAndHashAlgorithm algorithm = ChooseSignatureAlgorithm(_key, peerAlgorithms, tls13);
            if (algorithm == null)
            {
                return null;
            }

            Org.BouncyCastle.X509.X509Certificate[] certificates = _certificate.GetCertificates();

            Certificate chain;
            if (tls13)
            {
                CertificateEntry[] entries = new CertificateEntry[certificates.Length];
                for (int i = 0; i < entries.Length; i++)
                {
                    entries[i] = new CertificateEntry(_crypto.CreateCertificate(certificates[i].GetEncoded()), null);
                }

                chain = new Certificate(TlsUtilities.EmptyBytes, entries);
            }
            else
            {
                TlsCertificate[] list = new TlsCertificate[certificates.Length];
                for (int i = 0; i < list.Length; i++)
                {
                    list[i] = _crypto.CreateCertificate(certificates[i].GetEncoded());
                }

                chain = new Certificate(list);
            }

            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), _crypto, _key, chain, algorithm);
        }

        private static SignatureAndHashAlgorithm ChooseSignatureAlgorithm(AsymmetricKeyParameter key, IList<SignatureAndHashAlgorithm> offered, bool tls13)
        {
            if (offered == null)
            {
                if (tls13)
                {
                    return null;
                }

                // A TLS 1.2 peer that sent no signature_algorithms takes SHA-1 (RFC 5246, 7.4.1.4.1).
                if (key is RsaKeyParameters)
                {
                    return new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa);
                }

                if (key is ECPrivateKeyParameters)
                {
                    return new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa);
                }

                return null;
            }

            foreach (SignatureAndHashAlgorithm algorithm in offered)
            {
                if (Fits(key, algorithm, tls13))
                {
                    return algorithm;
                }
            }

            return null;
        }

        private static bool Fits(AsymmetricKeyParameter key, SignatureAndHashAlgorithm algorithm, bool tls13)
        {
            short signature = algorithm.Signature;

            if (key is RsaKeyParameters)
            {
                // TLS 1.3 signs the handshake with RSA-PSS only (RFC 8446, 4.2.3).
                return signature == SignatureAlgorithm.rsa_pss_rsae_sha256
                    || signature == SignatureAlgorithm.rsa_pss_rsae_sha384
                    || signature == SignatureAlgorithm.rsa_pss_rsae_sha512
                    || (!tls13 && signature == SignatureAlgorithm.rsa);
            }

            if (key is ECPrivateKeyParameters ec)
            {
                if (signature != SignatureAlgorithm.ecdsa)
                {
                    return false;
                }

                if (!tls13)
                {
                    return true;
                }

                // TLS 1.3 ties the hash to the curve (ecdsa_secp256r1_sha256...).
                int bits = ec.Parameters.Curve.FieldSize;
                short hash = algorithm.Hash;
                return (bits == 256 && hash == HashAlgorithm.sha256)
                    || (bits == 384 && hash == HashAlgorithm.sha384)
                    || (bits == 521 && hash == HashAlgorithm.sha512);
            }

            if (key is Ed25519PrivateKeyParameters)
            {
                return signature == SignatureAlgorithm.ed25519;
            }

            if (key is Ed448PrivateKeyParameters)
            {
                return signature == SignatureAlgorithm.ed448;
            }

            return false;
        }

        private static bool IsAddress(string host)
        {
            // An IPv4 literal (see CertificateVerifier.ParseIPv4), or an IPv6 one.
            return CertificateVerifier.ParseIPv4(host) != null || host.IndexOf(':') >= 0;
        }

        /// <summary>
        /// BouncyCastle's TLS client, configured as nanoFramework's SecureClientInit configures mbedTLS.
        /// </summary>
        private sealed class Client : DefaultTlsClient
        {
            private readonly SslNative _context;
            private readonly string _targetHost;

            internal Client(SslNative context, string targetHost)
                : base(context._crypto)
            {
                _context = context;
                _targetHost = targetHost;
            }

            protected override ProtocolVersion[] GetSupportedVersions()
            {
                return _context.SupportedVersions(base.GetSupportedVersions());
            }

            protected override int[] GetSupportedCipherSuites()
            {
                return TlsUtilities.GetSupportedCipherSuites(Crypto, ClientCipherSuites);
            }

            protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles)
            {
                return new List<int>(Groups);
            }

            protected override IList<ProtocolName> GetProtocolNames()
            {
                return new List<ProtocolName> { ProtocolName.Http_1_1 };
            }

            public override bool RequiresCloseNotify()
            {
                // Many servers close without one; the HTTP code knows where the data ends.
                return false;
            }

            protected override IList<ServerName> GetSniServerNames()
            {
                // Server Name Indication names a host, never an address (RFC 6066, 3).
                if (string.IsNullOrEmpty(_targetHost) || IsAddress(_targetHost))
                {
                    return null;
                }

                return new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(_targetHost)) };
            }

            public override TlsAuthentication GetAuthentication()
            {
                return new ClientAuthentication(this);
            }

            private sealed class ClientAuthentication : TlsAuthentication
            {
                private readonly Client _client;

                internal ClientAuthentication(Client client)
                {
                    _client = client;
                }

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    _client._context.VerifyPeer(serverCertificate.Certificate, _client._targetHost);
                }

                public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
                {
                    // The client certificate given to AuthenticateAsClient, if any.
                    return _client._context.Credentials(_client.m_context, certificateRequest.SupportedSignatureAlgorithms);
                }
            }
        }

        /// <summary>
        /// BouncyCastle's TLS server, configured as nanoFramework's SecureServerInit configures mbedTLS.
        /// </summary>
        private sealed class Server : DefaultTlsServer
        {
            private readonly SslNative _context;

            internal Server(SslNative context)
                : base(context._crypto)
            {
                _context = context;
            }

            protected override ProtocolVersion[] GetSupportedVersions()
            {
                return _context.SupportedVersions(base.GetSupportedVersions());
            }

            protected override int[] GetSupportedCipherSuites()
            {
                // The TLS 1.2 suites whose signature the server's key can make; TLS 1.3's don't depend on the key.
                return TlsUtilities.GetSupportedCipherSuites(Crypto, _context._key is RsaKeyParameters ? ServerCipherSuitesRsa : ServerCipherSuitesEcdsa);
            }

            public override int[] GetSupportedGroups()
            {
                return Groups;
            }

            public override TlsCredentials GetCredentials()
            {
                TlsCredentialedSigner signer = _context.Credentials(m_context, m_context.SecurityParameters.ClientSigAlgs);
                if (signer == null)
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure, "None of the client's signature algorithms fits the server's key.");
                }

                return signer;
            }

            public override CertificateRequest GetCertificateRequest()
            {
                if (_context._verification == SslVerification.NoVerification)
                {
                    return null;
                }

                IList<SignatureAndHashAlgorithm> algorithms = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);

                if (TlsUtilities.IsTlsV13(m_context))
                {
                    return new CertificateRequest(TlsUtilities.EmptyBytes, algorithms, null, null);
                }

                return new CertificateRequest(new short[] { ClientCertificateType.rsa_sign, ClientCertificateType.ecdsa_sign }, algorithms, null);
            }

            public override void NotifyClientCertificate(Certificate clientCertificate)
            {
                _context.VerifyPeer(clientCertificate, null);
            }
        }
    }
}
