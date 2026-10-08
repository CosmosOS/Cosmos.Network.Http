//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

// nanoFramework's System.Net SslStream (nanoFramework.System.Net/Security/SslStream.cs). Cosmos: the TLS that
// nanoFramework runs natively (SslNative, mbedTLS) is BouncyCastle's managed TLS, in SslNative.cs: .NET's SslStream
// needs OpenSSL, which a Cosmos kernel doesn't have. Each native call becomes a call to the SslNative object the
// stream holds in place of nanoFramework's SSL context handle. It derives from .NET's NetworkStream, which Cosmos
// plugs, where nanoFramework's derives from its own.

using System.IO;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Cosmos.Network.Http
{
    /// <summary>
    /// Provides a stream used for client-server communication that uses the Secure Socket Layer (SSL) security 
    /// protocol to authenticate the server and optionally the client.
    /// </summary>
    /// <remarks>
    /// Cosmos: internal, so it doesn't clash with System.Net.Security.SslStream.
    /// </remarks>
    internal class SslStream : NetworkStream
    {
        private SslVerification _sslVerification;
        private bool _useStoredDeviceCertificate = false;

        // Internal flags
        // Cosmos: the TLS session, null where nanoFramework's native context handle is -1.
        private SslNative _sslContext;
        private bool _isServer;

        // Cosmos: nanoFramework's NetworkStream has it, .NET's keeps its own private.
        private bool _disposed;

        /// <summary>
        /// Option for SSL verification.
        /// The default behaviour is <see cref="SslVerification.CertificateRequired"/>.
        /// </summary>
        public SslVerification SslVerification { get => _sslVerification; set => _sslVerification = value; }

        /// <summary>
        /// Option to use the certificate stored in the device as client or server certificate.
        /// The default option is <see langword="false"/>.
        /// </summary>
        /// <remarks>
        /// This property is exclusive of .NET nanoFramework.
        /// In case there is no device certificate stored, the authentication will use whatever is provided (or not) in the parameter of the method being called.
        /// Cosmos: a kernel has no device certificate store, so this changes nothing.
        /// </remarks>
        public bool UseStoredDeviceCertificate { get => _useStoredDeviceCertificate; set => _useStoredDeviceCertificate = value; }

        //--//

        /// <summary>
        /// Initializes a new instance of the SslStream class using the specified Socket.
        /// </summary>
        /// <param name="socket">A valid socket that currently has a TCP connection.</param>
        /// <exception cref="ArgumentNullException"><paramref name="socket"/> is <see langword="null"/>.</exception>
        /// <exception cref="IOException"><paramref name="socket"/> is not connected. -or- The <see cref="Socket.SocketType"/> property of <paramref name="socket"/> is not <see cref="SocketType.Stream"/>.</exception>
        /// <remarks>
        /// The SslStream maintains the lifetime of the socket. When the SslStream object is disposed, 
        /// the underlying TCP socket will be closed.
        /// </remarks>
        public SslStream(Socket socket)
            : base(socket, false)
        {
            _sslContext = null;
            _isServer = false;

            _sslVerification = SslVerification.CertificateRequired;
        }

        /// <summary>
        /// Called by clients to authenticate the server and optionally the client in a client-server connection.
        /// The authentication process uses the specified SSL protocols.
        /// </summary>
        /// <param name="targetHost">The name of the server that will share this SslStream.</param>
        /// <param name="enabledSslProtocols">The <see cref="SslProtocols"/> value that represents the protocol used for authentication.</param>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The TLS handshake failed: no common protocol or cipher suite, a certificate that doesn't verify, or an alert from the peer.</exception>
        /// <exception cref="IOException">The connection was closed, or nothing was received for <see cref="NetworkStream.ReadTimeout"/>, during the handshake.</exception>
        public void AuthenticateAsClient(
            string targetHost,
            SslProtocols enabledSslProtocols)
        {
            Authenticate(false,
                         targetHost,
                         null,
                         null,
                         enabledSslProtocols);
        }

        /// <summary>
        /// Called by clients to authenticate the server and optionally the client in a client-server connection.
        /// The authentication process uses the specified certificate collections and SSL protocols.
        /// </summary>
        /// <param name="targetHost">The name of the server that will share this SslStream.</param>
        /// <param name="clientCertificate">The client certificate.</param>
        /// <param name="enabledSslProtocols">The <see cref="SslProtocols"/> value that represents the protocol used for authentication.</param>
        /// <remarks>
        /// Instead of providing the client certificate in the <paramref name="clientCertificate"/> parameter the <see cref="UseStoredDeviceCertificate"/> property can be used to use the certificate stored in the device.
        /// </remarks>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The TLS handshake failed: no common protocol or cipher suite, a certificate that doesn't verify, or an alert from the peer.</exception>
        /// <exception cref="IOException">The connection was closed, or nothing was received for <see cref="NetworkStream.ReadTimeout"/>, during the handshake.</exception>
        public void AuthenticateAsClient(
            string targetHost,
            X509Certificate clientCertificate,
            SslProtocols enabledSslProtocols)
        {
            Authenticate(false,
                         targetHost,
                         clientCertificate,
                         null,
                         enabledSslProtocols);
        }

        /// <summary>
        /// Called by clients to authenticate the server and optionally the client in a client-server connection.
        /// The authentication process uses the specified certificate collections and SSL protocols.
        /// </summary>
        /// <param name="targetHost">The name of the server that will share this SslStream.</param>
        /// <param name="clientCertificate">The client certificate.</param>
        /// <param name="ca">Certificate Authority certificate to use for authentication with the server.</param>
        /// <param name="enabledSslProtocols">The <see cref="SslProtocols"/> value that represents the protocol used for authentication.</param>
        /// <remarks>
        /// Instead of providing the client certificate in the <paramref name="clientCertificate"/> parameter the <see cref="UseStoredDeviceCertificate"/> property can be used to use the certificate stored in the device.
        /// </remarks>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The TLS handshake failed: no common protocol or cipher suite, a certificate that doesn't verify, or an alert from the peer.</exception>
        /// <exception cref="IOException">The connection was closed, or nothing was received for <see cref="NetworkStream.ReadTimeout"/>, during the handshake.</exception>
        public void AuthenticateAsClient(
            string targetHost,
            X509Certificate clientCertificate,
            X509Certificate ca,
            SslProtocols enabledSslProtocols)
        {
            Authenticate(false,
                         targetHost,
                         clientCertificate,
                         ca,
                         enabledSslProtocols);
        }

        /// <summary>
        /// Called by servers to authenticate the server and optionally the client in a client-server connection using the specified certificate,
        /// verification requirements and security protocol.
        /// </summary>
        /// <param name="serverCertificate">The certificate used to authenticate the server.</param>
        /// <param name="enabledSslProtocols">The protocols that may be used for authentication.</param>
        /// <remarks>
        /// Instead of providing the server certificate in the <paramref name="serverCertificate"/> parameter the <see cref="UseStoredDeviceCertificate"/> property can be used to use the certificate stored in the device.
        /// </remarks>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The TLS handshake failed: no common protocol or cipher suite, a certificate that doesn't verify, or an alert from the peer.</exception>
        /// <exception cref="IOException">The connection was closed, or nothing was received for <see cref="NetworkStream.ReadTimeout"/>, during the handshake.</exception>
        public void AuthenticateAsServer(
            X509Certificate serverCertificate,
            SslProtocols enabledSslProtocols)
        {
            Authenticate(true,
                         "",
                         serverCertificate,
                         null,
                         enabledSslProtocols);
        }

        /// <summary>
        /// Called by servers to authenticate the server and optionally the client in a client-server connection using the specified certificates, requirements and security protocol.
        /// </summary>
        /// <param name="serverCertificate">The X509Certificate used to authenticate the server.</param>
        /// <param name="clientCertificateRequired">A <see cref="Boolean"/> value that specifies whether the client is asked for a certificate for authentication. Note that this is only a request — if no certificate is provided, the server still accepts the connection request.</param>
        /// <param name="enabledSslProtocols">The protocols that may be used for authentication.</param>
        /// <remarks>
        /// Instead of providing the server certificate in the <paramref name="serverCertificate"/> parameter the <see cref="UseStoredDeviceCertificate"/> property can be used to use the certificate stored in the device.
        /// </remarks>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The TLS handshake failed: no common protocol or cipher suite, a certificate that doesn't verify, or an alert from the peer.</exception>
        /// <exception cref="IOException">The connection was closed, or nothing was received for <see cref="NetworkStream.ReadTimeout"/>, during the handshake.</exception>
        public void AuthenticateAsServer(
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            SslProtocols enabledSslProtocols)
        {
            SslVerification = clientCertificateRequired ? SslVerification.VerifyClientOnce : SslVerification.NoVerification;

            Authenticate(true,
                         "",
                         serverCertificate,
                         null,
                         enabledSslProtocols);
        }

        internal void Authenticate(bool isServer, string targetHost, X509Certificate certificate, X509Certificate ca, SslProtocols enabledSslProtocols)
        {
            if (null != _sslContext) throw new InvalidOperationException("The stream is already authenticated.");

            _isServer = isServer;

            try
            {
                if (isServer)
                {
                    _sslContext = SslNative.SecureServerInit(
                        enabledSslProtocols,
                        _sslVerification,
                        certificate,
                        ca,
                        _useStoredDeviceCertificate);

                    _sslContext.SecureAccept(this);
                }
                else
                {
                    _sslContext = SslNative.SecureClientInit(
                        enabledSslProtocols,
                        _sslVerification,
                        certificate,
                        ca,
                        _useStoredDeviceCertificate);

                    _sslContext.SecureConnect(targetHost, this);
                }
            }
            catch
            {
                if (_sslContext != null)
                {
                    _sslContext.ExitSecureContext();
                    _sslContext = null;
                }

                throw;
            }
        }

        /// <summary>
        /// Cosmos: starts authenticating as the server without waiting for the client, for HttpListener, whose one
        /// thread serves every connection: <see cref="AdvanceAuthentication"/> goes on with it.
        /// </summary>
        /// <param name="serverCertificate">The certificate used to authenticate the server.</param>
        /// <param name="enabledSslProtocols">The protocols that may be used for authentication.</param>
        /// <exception cref="InvalidOperationException">Authentication has already been performed on this stream.</exception>
        /// <exception cref="AuthenticationException">The certificate can't be used.</exception>
        internal void BeginAuthenticateAsServer(X509Certificate serverCertificate, SslProtocols enabledSslProtocols)
        {
            if (null != _sslContext) throw new InvalidOperationException("The stream is already authenticated.");

            _isServer = true;
            _sslVerification = SslVerification.NoVerification;

            try
            {
                _sslContext = SslNative.SecureServerInit(enabledSslProtocols, _sslVerification, serverCertificate, null, _useStoredDeviceCertificate);
                _sslContext.BeginAccept(this);
            }
            catch
            {
                _sslContext = null;
                throw;
            }
        }

        /// <summary>
        /// Cosmos: goes on authenticating as the server with what the client has sent, without waiting.
        /// </summary>
        /// <returns>Whether the stream is authenticated.</returns>
        /// <exception cref="AuthenticationException">The TLS handshake failed.</exception>
        /// <exception cref="IOException">The connection was closed.</exception>
        internal bool AdvanceAuthentication()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(SslStream));

            return Context.AdvanceHandshake();
        }

        /// <summary>
        /// Gets a value that indicates whether the local side of the connection used by this SslStream was authenticated as the server.
        /// </summary>
        public bool IsServer { get { return _isServer; } }

        /// <summary>
        /// Cosmos: the session, read once, as a Dispose on another thread may clear it: an exception rather than a null
        /// dereference (a kernel panic on Cosmos).
        /// </summary>
        private SslNative Context
        {
            get
            {
                SslNative context = _sslContext;
                if (context == null)
                {
                    if (_disposed) throw new ObjectDisposedException(nameof(SslStream));
                    throw new IOException("The stream is not authenticated.");
                }

                return context;
            }
        }

        /// <summary>
        /// Gets the number of bytes of decrypted data available to be read from the stream.
        /// </summary>
        public override long Length
        {
            get
            {
                return Context.DataAvailable();
            }
        }

        /// <summary>
        /// Gets a value that indicates whether decrypted data is available on the stream to be read.
        /// </summary>
        public override bool DataAvailable
        {
            get
            {
                return Context.DataAvailable() > 0;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        ~SslStream()
        {
            // Do not re-create Dispose clean-up code here.
            // Calling Dispose(false) is optimal in terms of
            // readability and maintainability.
            Dispose(false);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the SslStream and optionally releases the managed resources. 
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        /// <remarks>
        /// Cosmos: not synchronized, as nanoFramework's is: a Cosmos kernel doesn't release the lock while an exception
        /// unwinds.
        /// </remarks>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                SslNative context = _sslContext;
                _sslContext = null;

                // Cosmos: nanoFramework's native SecureCloseSocket sends the close_notify alert and closes the socket,
                // which has no native handle to mark here.
                if (context != null)
                {
                    context.SecureCloseSocket();
                    context.ExitSecureContext();
                }
                else
                {
                    SslNative.CloseSocket(Socket);
                }

                // Cosmos: .NET's NetworkStream marks itself disposed too; it doesn't own the socket, closed above.
                base.Dispose(disposing);
            }
        }

        /// <summary>
        /// Reads data from this stream and stores it in the specified array.
        /// </summary>
        /// <param name="buffer">An array that receives the bytes read from this stream.</param>
        /// <param name="offset">An integer that contains the zero-based location in buffer at which to begin storing the data read from this stream.</param>
        /// <param name="count">The maximum number of bytes to read from this stream.</param>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException();
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SslStream));
            }

            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (count < 0 || count > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException();
            }

            return Context.SecureRead(buffer, offset, count, ReadTimeout);
        }

        /// <summary>
        /// Write the specified number of bytes to the underlying stream using the specified buffer and offset.
        /// </summary>
        /// <param name="buffer">An array that supplies the bytes written to the stream.</param>
        /// <param name="offset">The zero-based location in buffer at which to begin reading bytes to be written to the stream.</param>
        /// <param name="count">The number of bytes to read from buffer.</param>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <para>
        /// <paramref name="offset"/> or <paramref name="count"/> is less than zero
        /// </para>
        /// <para>
        /// -or-
        /// </para>
        /// <para>
        /// <paramref name="offset"/> is greater than the length of <paramref name="buffer"/>.
        /// </para>
        /// <para>
        /// -or-
        /// </para>
        /// <para>
        /// <paramref name="offset"/> + <paramref name="count"/> is greater than the length of <paramref name="buffer"/>.
        /// </para>
        /// </exception>
        /// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
        /// <exception cref="IOException">The write operation failed.</exception>
        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException();
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SslStream));
            }

            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (count < 0 || count > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException();
            }

            int written = Context.SecureWrite(buffer, offset, count, WriteTimeout);

            if (written <= 0 && count > 0)
            {
                throw new IOException("The TLS write failed.");
            }
        }
    }
}
