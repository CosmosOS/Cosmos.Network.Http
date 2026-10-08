//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

namespace Cosmos.Network.Http
{
    using System.Collections;
    using System.Diagnostics;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;

    /// <summary>
    /// Provides a simple, programmatically controlled HTTP protocol listener.
    /// This class cannot be inherited.
    /// </summary>
    /// <remarks>
    /// This class enables using a socket to receive data that uses the HTTP
    /// protocol.
    /// </remarks>
    public class HttpListener
    {
        private readonly object lockObj;

        /// <summary>
        /// Indicates whether the listener is waiting on an http or https
        /// connection.
        /// </summary>
        bool m_IsHttpsConnection;

        /// <summary>
        /// The certificate to send during https authentication.
        /// </summary>
        X509Certificate m_httpsCert;

        /// <summary>
        /// This value is the number of connections that can be ready but are
        /// not retrieved through the Accept call.
        /// </summary>
        /// <remarks>
        /// This value is passed to the <b>Listen</b> method of the socket.
        /// </remarks>
        private const int MaxCountOfPendingConnections = 10;

        /// <summary>
        /// Server socket for incoming connections.
        /// </summary>
        private Socket m_listener;

        /// <summary>
        /// The MAXIMUM length, in kilobytes (1024 bytes), of the request
        /// headers.
        /// </summary>
        internal int m_maxResponseHeadersLen;

        /// <summary>
        /// Event that indicates arrival of new event from client.
        /// </summary>
        // Cosmos: the connections waiting for a request, which GetContext watches where nanoFramework starts a thread
        // for each (WaitingConnection).
        private ArrayList m_WaitingConnections;

        // Cosmos: the listener the current thread serves (calls GetContext for, and handles the requests of), and
        // whether one does: the sockets are that thread's alone, as Cosmos's network stack takes no lock. Stop, Close
        // and Abort on another thread only ask; the serving thread closes them on its way into or out of GetContext,
        // when a response hands a connection back, or in its own Stop or Close.
        [ThreadStatic]
        private static HttpListener t_served;
        private volatile bool m_HasServingThread;

        private bool OnServingThread => !m_HasServingThread || t_served == this;

        // Cosmos: the https connections whose TLS handshake is under way (Handshaking), which GetContext advances.
        private ArrayList m_Handshaking;

        // Cosmos: whether Abort, called while a thread waited in GetContext, left that thread to close the connections.
        internal volatile bool m_AbortPending;

        // Cosmos: whether the listening socket was closed (1), claimed with Interlocked so that one thread closes it:
        // Stop's, or the one in GetContext.
        private int m_ListenerClosed = 1;

        /// <summary>
        /// The queue of connected networks streams with pending client data.
        /// </summary>
        Queue m_InputStreamsQueue;

        /// <summary>
        /// Port number for the server socket.
        /// </summary>
        private int m_Port;

        /// <summary>
        /// the local endpoint to bind the socket to. if Null the default is used
        /// </summary>
        private IPAddress m_localEndpointIP;

        /// <summary>
        /// Indicates whether the listener is started and is currently accepting
        /// connections.
        /// </summary>
        private volatile bool m_ServiceRunning;

        /// <summary>
        /// Indicates whether the listener has been closed
        /// </summary>
        private bool m_Closed;

        /// <summary>
        /// Array of connected client sockets.
        /// </summary>
        private ArrayList m_ClientStreams;

        /// <summary>
        /// SslProtocol which shall be used.
        /// </summary>
        private SslProtocols m_sslProtocols = SslProtocols.None;

#pragma warning disable S2292 // Trivial properties should be auto-implemented
        /// <summary>
        /// Gets or sets the TLS/SSL protocol used by the <see cref="HttpListener"/> class.
        /// </summary>
        /// <value>
        /// One of the values defined in the <see cref="Security.SslProtocols"/> enumeration.
        /// </value>
        /// <remarks>
        /// This property is specific to nanoFramework. There is no equivalent in the .NET API.
        /// </remarks>
        public SslProtocols SslProtocols
#pragma warning restore S2292 // Trivial properties should be auto-implemented 
        // nanoFramework doesn't support auto-properties
        {
            get { return m_sslProtocols; }
            set { m_sslProtocols = value; }
        }

        /// <summary>
        /// Creates an HTTP or HTTPS listener on the standard ports.
        /// </summary>
        /// <param name="prefix">Prefix ( http or https ) to start listen</param>
        /// <remarks>In the desktop version of .NET, the constructor for this
        /// class has no arguments.</remarks>
        public HttpListener(string prefix)
        {
            lockObj = new object();

            InitListener(prefix, -1);
        }

        /// <summary>
        /// Creates an HTTP or HTTPS listener on the specified port.
        /// </summary>
        /// <param name="prefix">The prefix for the service, either "http" or
        /// "https".</param>
        /// <param name="port">The port to start listening on.  If -1, the
        /// default port is used (port 80 for http, or port 443 for https).
        /// </param>
        /// <param name="localEndpointIP"> The local endpoint to bind the socket to. If Null the default is used
        /// </param>
        /// <remarks>In the desktop version of .NET, the constructor for this
        /// class has no arguments.</remarks>
        public HttpListener(string prefix, int port, IPAddress localEndpointIP = null)
        {
            lockObj = new object();

            InitListener(prefix, port, localEndpointIP);
        }

        /// <summary>
        /// Initializes the listener.
        /// </summary>
        /// <param name="prefix">The prefix for the service, either "http" or
        /// "https".</param>
        /// <param name="port">The port to start listening on.  If -1, the
        /// default port is used (port 80 for http, or port 443 for https).
        /// </param>
        private void InitListener(string prefix, int port, IPAddress localEndpointIp = null)
        {
            // Cosmos: .NET's Uri schemes are not constants, and its Uri has no default port fields.
            string scheme = prefix.ToLower();
            if (scheme == Uri.UriSchemeHttp || scheme == Uri.UriSchemeWs)
            {
                m_IsHttpsConnection = false;
                m_Port = 80;
            }
            else if (scheme == Uri.UriSchemeHttps || scheme == Uri.UriSchemeWss)
            {
                m_IsHttpsConnection = true;
                m_Port = 443;
            }
            else
            {
                throw new ArgumentException("Prefix should be http or https");
            }

            if (port != -1)
            {
                m_Port = port;
            }

            if (localEndpointIp != null)
            {
                m_localEndpointIP = localEndpointIp;
            }
            // Default members initialization
            m_maxResponseHeadersLen = 4;
            m_WaitingConnections = new ArrayList();
            m_Handshaking = new ArrayList();
            m_InputStreamsQueue = new Queue();
            m_ClientStreams = new ArrayList();
        }

        /// <summary>
        /// Adds a new output stream to the list of connected streams.
        /// </summary>
        /// <remarks>This is an internal function, not visible to the user.
        /// </remarks>
        /// <param name="clientStream">The stream to add.</param>
        internal void AddClientStream(OutputNetworkStreamWrapper clientStream)
        {
            lock (m_ClientStreams)
            {
                m_ClientStreams.Add(clientStream);
            }
        }

        /// <summary>
        /// Removes the specified output stream from the list of connected
        /// streams.
        /// </summary>
        /// <param name="clientStream">The stream to remove.</param>
        internal void RemoveClientStream(OutputNetworkStreamWrapper clientStream)
        {
            lock (m_ClientStreams)
            {
                for (int i = 0; i < m_ClientStreams.Count; i++)
                {
                    if (clientStream == m_ClientStreams[i])
                    {
                        m_ClientStreams.RemoveAt(i);
                        break;
                    }
                }
            }
        }

        // Cosmos: nanoFramework accepts on a thread of its own, waits for a kept-alive connection's next request on a
        // thread per connection blocked in Socket.Poll, and wakes GetContext with an AutoResetEvent. On a Cosmos kernel
        // a thread's stack is never freed, the network stack has no locks, and two threads throwing at once halt the
        // kernel (a failed TLS handshake throws). So the thread in GetContext does it all: it
        // accepts, runs the TLS handshakes and watches the connections waiting for a request, and no other thread
        // touches the sockets.

        // How long GetContext sleeps between two rounds with nothing to do: each Thread.Sleep writes a line to a Cosmos
        // kernel's serial port (its LowLevelMonitor plug logs), which shorter sleeps would keep busy.
        private const int IdleSleepMilliseconds = 50;

        // How long a client may take to send what a request still lacks: one thread serves every connection.
        private const int ClientReadTimeout = 10000;

        /// <summary>
        /// A connection waiting for its next request, and since when.
        /// </summary>
        private class WaitingConnection
        {
            internal WaitingConnection(OutputNetworkStreamWrapper stream)
            {
                m_stream = stream;
                m_since = Stopwatch.GetTimestamp();
            }

            internal readonly OutputNetworkStreamWrapper m_stream;
            internal readonly long m_since;
        }

        // How long GetContext sleeps between two rounds while TLS handshakes are under way, which take a few round trips.
        private const int HandshakeSleepMilliseconds = 10;

        /// <summary>
        /// An https connection whose TLS handshake is under way, and since when.
        /// </summary>
        private class Handshaking
        {
            internal Handshaking(Socket socket, SslStream stream)
            {
                m_socket = socket;
                m_stream = stream;
                m_since = Stopwatch.GetTimestamp();
            }

            internal readonly Socket m_socket;
            internal readonly SslStream m_stream;
            internal readonly long m_since;
        }

        /// <summary>
        /// Advances the TLS handshakes under way with what their clients sent, without waiting: those complete wait for
        /// a request, those failed or too slow are closed.
        /// </summary>
        /// <returns>Whether a handshake completed or was closed.</returns>
        /// <remarks>Cosmos: nanoFramework's accept thread runs each handshake to its end, which GetContext's thread, the
        /// one serving every connection, can't wait for.</remarks>
        private bool CheckHandshakes()
        {
            bool changed = false;

            for (int i = m_Handshaking.Count - 1; i >= 0; i--)
            {
                Handshaking handshaking = (Handshaking)m_Handshaking[i];

                bool complete = false;
                bool failed;
                try
                {
                    complete = handshaking.m_stream.AdvanceAuthentication();
                    failed = !complete && Stopwatch.GetElapsedTime(handshaking.m_since).TotalMilliseconds > ClientReadTimeout;
                }
                catch
                {
                    // An alert, a certificate, or a client gone.
                    failed = true;
                }

                if (complete)
                {
                    m_Handshaking.RemoveAt(i);
                    AddToWaitingConnections(new OutputNetworkStreamWrapper(handshaking.m_socket, handshaking.m_stream));
                    changed = true;
                }
                else if (failed)
                {
                    m_Handshaking.RemoveAt(i);
                    DisposeQuietly(handshaking.m_stream);
                    changed = true;
                }
            }

            return changed;
        }

        /// <summary>
        /// Adds a connection to those waiting for a request: a new one, or one kept alive after a response.
        /// </summary>
        internal void AddToWaitingConnections(OutputNetworkStreamWrapper outputStream)
        {
            // Cosmos: GetContext watches it, where nanoFramework starts a thread to wait for its data. Not once stopped:
            // nothing would.
            if (!m_ServiceRunning)
            {
                DisposeQuietly(outputStream);

                // Cosmos: on the serving thread, after a Stop from another: the listening socket and the other waiting
                // connections close with this one.
                if (OnServingThread)
                {
                    CloseListenerSocket();
                }

                return;
            }

            m_WaitingConnections.Add(new WaitingConnection(outputStream));
        }

        /// <summary>
        /// Queues the waiting connections whose request has arrived, and closes those the client closed or left idle.
        /// </summary>
        /// <returns>Whether a connection was queued or closed.</returns>
        private bool CheckWaitingConnections()
        {
            bool changed = false;

            for (int i = m_WaitingConnections.Count - 1; i >= 0; i--)
            {
                WaitingConnection waiting = (WaitingConnection)m_WaitingConnections[i];
                OutputNetworkStreamWrapper outputStream = waiting.m_stream;

                bool arrived = false;
                bool closed;
                try
                {
                    // Cosmos: closed by HttpListenerContext.Close or its OutputStream's Close since its response, which
                    // leaves no stream: nanoFramework's thread then fails on it, a null dereference here (a kernel
                    // panic on Cosmos, not an exception).
                    NetworkStream stream = outputStream.m_Stream;
                    Socket socket = outputStream.m_Socket;
                    if (stream == null || socket == null)
                    {
                        closed = true;
                    }
                    else
                    {
                        // The stream's DataAvailable: decrypted data, for https. Cosmos: or what the connection's
                        // reader already took from it, after the previous request.
                        arrived = outputStream.HasBufferedInput || stream.DataAvailable;
                        closed = !arrived
                            && ((socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0)
                                || Stopwatch.GetElapsedTime(waiting.m_since).TotalMilliseconds > HttpConstants.DefaultKeepAliveMilliseconds);
                    }
                }
                catch
                {
                    // A reset, or a TLS alert.
                    closed = true;
                }

                if (arrived)
                {
                    m_WaitingConnections.RemoveAt(i);
                    m_InputStreamsQueue.Enqueue(outputStream);
                    changed = true;
                }
                else if (closed)
                {
                    m_WaitingConnections.RemoveAt(i);
                    DisposeQuietly(outputStream);
                    changed = true;
                }
            }

            return changed;
        }

        /// <summary>
        /// Shuts down the <itemref>HttpListener</itemref> object immediately,
        /// discarding all currently queued requests.
        /// </summary>
        /// <remarks>This method disposes of all resources held by this
        /// listener.  Any pending requests are unable to complete.  To shut
        /// down the <itemref>HttpListener</itemref> object after processing
        /// currently queued requests, use the
        /// <see cref='Close'/> method.
        /// <para>
        /// After calling this method, you will receive an
        /// <see cref='ObjectDisposedException'/> if you attempt to use this
        /// <itemref>HttpListener</itemref>.
        /// </para>
        /// </remarks>
        public void Abort()
        {
            // First we shut down the service.
            Close();

            // Cosmos: closed by the serving thread, when another calls this (see t_served).
            m_AbortPending = true;
            if (OnServingThread)
            {
                CloseClientStreams();
            }
        }

        /// <summary>
        /// Cosmos: what a Stop or an Abort from another thread left to the serving thread.
        /// </summary>
        private void CloseOnServingThread()
        {
            CloseListenerSocket();

            if (m_AbortPending)
            {
                CloseClientStreams();
            }
        }

        /// <summary>
        /// Closes the connections whose response is under way.
        /// </summary>
        private void CloseClientStreams()
        {
            m_AbortPending = false;

            // Now we need to go through list of all client sockets and close all of them.
            // This will cause exceptions on read/write operations on these sockets.
            // Cosmos: no accept thread to join, and no lock, which an exception would leave held on a Cosmos kernel.
            // A stream closed so throws ObjectDisposedException on its next use, where nanoFramework's dereferences null.
            object[] streams;
            lock (m_ClientStreams)
            {
                streams = m_ClientStreams.ToArray();
                m_ClientStreams.Clear();
            }

            foreach (OutputNetworkStreamWrapper netStream in streams)
            {
                DisposeQuietly(netStream);
            }
        }

        /// <summary>
        /// Accepts the connection waiting on the listening socket, if any.
        /// </summary>
        /// <returns>Whether a connection was accepted.</returns>
        /// <remarks>Cosmos: what nanoFramework's accept thread does for each connection, called by GetContext. The
        /// connection then waits for its request with the kept-alive ones, so a client that connects and sends
        /// nothing, as a browser does ahead of time, doesn't hold the thread.</remarks>
        private bool AcceptPendingConnection()
        {
            Socket listener = m_listener;
            if (listener == null || !listener.Poll(0, SelectMode.SelectRead))
            {
                return false;
            }

            Socket clientSock;
            try
            {
                clientSock = listener.Accept();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return false;
            }

            // Cosmos: no NoDelay option, which faults on Cosmos's sockets (see Start).

            // Need to create NetworkStream or SSL stream depending on protocol used.
            NetworkStream netStream = null;

            try
            {
                if (!m_IsHttpsConnection)
                {
                    // This is case of normal HTTP. Create network stream.
                    netStream = new NetworkStream(clientSock, true);
                }
                else
                {
                    // This is the case of https.
                    // Once connection established need to create secure stream and authenticate server.
                    SslStream sslStream = new SslStream(clientSock);
                    netStream = sslStream;
                    netStream.ReadTimeout = ClientReadTimeout;

                    // Throws exception if this fails
                    // pass the server certificate
                    // do not require client certificate
                    // Cosmos: started only; CheckHandshakes goes on with it as the client answers.
                    sslStream.BeginAuthenticateAsServer(m_httpsCert, m_sslProtocols);
                    m_Handshaking.Add(new Handshaking(clientSock, sslStream));
                    return true;
                }

                // Cosmos: nanoFramework sets it for https only.
                netStream.ReadTimeout = ClientReadTimeout;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);

                if (netStream != null)
                {
                    DisposeQuietly(netStream);
                }
                else
                {
                    SslNative.CloseSocket(clientSock);
                }

                return true;
            }

            AddToWaitingConnections(new OutputNetworkStreamWrapper(clientSock, netStream));
            return true;
        }

        private static void DisposeQuietly(IDisposable disposable)
        {
            try
            {
                disposable.Dispose();
            }
            catch
            {
                // Closed already, or reset by the client.
            }
        }

        /// <summary>
        /// Closes the listening socket and the connections waiting for a request.
        /// </summary>
        private void CloseListenerSocket()
        {
            if (Interlocked.Exchange(ref m_ListenerClosed, 1) != 0)
            {
                return;
            }

            Socket listener = m_listener;
            m_listener = null;

            if (listener != null)
            {
                SslNative.CloseSocket(listener);
            }

            for (int i = 0; i < m_WaitingConnections.Count; i++)
            {
                DisposeQuietly(((WaitingConnection)m_WaitingConnections[i]).m_stream);
            }
            m_WaitingConnections.Clear();

            for (int i = 0; i < m_Handshaking.Count; i++)
            {
                DisposeQuietly(((Handshaking)m_Handshaking[i]).m_stream);
            }
            m_Handshaking.Clear();

            while (m_InputStreamsQueue.Count > 0)
            {
                DisposeQuietly((OutputNetworkStreamWrapper)m_InputStreamsQueue.Dequeue());
            }
        }

        /// <summary>
        /// Allows this instance to receive incoming requests.
        /// </summary>
        /// <remarks>This method must be called before you call the
        /// <see cref="GetContext"/> method.   If
        /// the service was already started, the call has no effect.  After you
        /// have started an <itemref>HttpListener</itemref> object, you can use
        /// the <see cref='Stop'/> method to stop it.
        /// </remarks>
        public void Start()
        {
            // Cosmos: no lock (an exception would leave it held on a Cosmos kernel), and no accept thread.
            if (m_Closed) throw new ObjectDisposedException(nameof(HttpListener));

            // If service was already started, the call has no effect.
            if (m_ServiceRunning)
            {
                return;
            }

            // Cosmos: a stop the serving thread hasn't carried out yet is undone, its listening socket kept: another
            // bound to the port would leave that one open for good.
            if (Volatile.Read(ref m_ListenerClosed) == 0)
            {
                m_ServiceRunning = true;
                return;
            }

            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Cosmos: no NoDelay nor ReuseAddress option. Cosmos's sockets have no native handle for SetSocketOption
            // to reach, and it faults on the null one (a kernel panic, which no catch stops). Cosmos's TCP sends every
            // write at once and keeps no TIME_WAIT, which leaves those options nothing to do.

            // Cosmos: nanoFramework's GetDefaultLocalAddress (the device's address) is .NET's Any.
            IPAddress addr = m_localEndpointIP ?? IPAddress.Any;

            IPEndPoint endPoint = new IPEndPoint(addr, m_Port);

            try
            {
                listener.Bind(endPoint);

                // Starts to listen to maximum of 10 connections.
                listener.Listen(MaxCountOfPendingConnections);
            }
            catch
            {
                SslNative.CloseSocket(listener);
                throw;
            }

            m_listener = listener;
            Interlocked.Exchange(ref m_ListenerClosed, 0);
            m_ServiceRunning = true;
        }

        /// <summary>
        /// Shuts down the <itemref>HttpListener</itemref>.
        /// </summary>
        /// <remarks>After calling this method, you can no longer use the
        /// <itemref>HttpListener</itemref> object.  To temporarily pause an
        /// <itemref>HttpListener</itemref> object, use the
        /// <see cref='Stop'/> method.
        /// <para>
        /// Cosmos: as <see cref="Stop"/>, the requests that arrived but weren't returned by GetContext yet are closed
        /// unanswered; the one being handled is answered.
        /// </para>
        /// </remarks>
        public void Close()
        {
            // close does not throw
            if (!m_Closed)
            {
                Stop();
            }

            m_Closed = true;
        }

        /// <summary>
        /// Causes this instance to stop receiving incoming requests.
        /// </summary>
        /// <remarks>If this instance is already stopped, calling this method
        /// has no effect.
        /// <para>
        /// After you have stopped an <itemref>HttpListener</itemref> object,
        /// you can use the <see cref='Start'/> method
        /// to restart it.
        /// </para>
        /// <para>
        /// Cosmos: called from another thread than the one serving (calling <see cref="GetContext"/>), it leaves the
        /// sockets to that one: waiting in GetContext, it closes them and returns null within a round (50 ms); handling a
        /// request, it closes them once the response is closed, or in its next GetContext call, which throws
        /// InvalidOperationException, or in its own Close.
        /// </para>
        /// </remarks>
        public void Stop()
        {
            if (m_Closed) throw new ObjectDisposedException(nameof(HttpListener));

            m_ServiceRunning = false;

            // We close the server socket that listen for incoming connection.
            // Cosmos: and the connections waiting for a request, on the serving thread (see t_served); the request
            // being handled is answered.
            if (OnServingThread)
            {
                CloseListenerSocket();
            }
        }

        /// <summary>
        /// Waits for an incoming request and returns when one is received.
        /// </summary>
        /// <returns>
        /// An <see cref="HttpListenerContext"/> object that
        /// represents a client request, or <see langword="null"/> once the listener is stopped.
        /// </returns>
        /// <exception cref="SocketException">A socket call failed. Check the
        /// exception's ErrorCode property to determine the cause of the exception.</exception>
        /// <exception cref="InvalidOperationException">This object has not been started or is
        /// currently stopped or The HttpListener does not have any Uniform Resource Identifier
        /// (URI) prefixes to respond to.</exception>
        /// <exception cref="ObjectDisposedException">This object is closed.</exception>
        /// <remarks>
        /// Cosmos: the connections are accepted, and the TLS handshakes run, on the thread that calls this method,
        /// which must be the one using the contexts it returns. It sleeps when nothing is pending, so it must not be
        /// a Cosmos kernel's main loop.
        /// </remarks>
        /// <example>This example shows how to call the
        /// <itemref>GetContext</itemref> method.
        /// <code>
        /// HttpListener myListener = new HttpListener("http", -1);
        /// myListener.Start();
        /// while (true)
        /// {
        ///     HttpListenerResponse response = null;
        ///     try
        ///     {
        ///         Debug.Print("Waiting for requests");
        ///         HttpListenerContext context = myListener.GetContext();
        /// </code>
        /// </example>
        public HttpListenerContext GetContext()
        {
            if (m_Closed) throw new ObjectDisposedException(nameof(HttpListener));

            // Cosmos: this thread serves the listener (see t_served).
            t_served = this;
            m_HasServingThread = true;

            if (!m_ServiceRunning)
            {
                // Cosmos: stopped from another thread while this one served a request: the sockets are its to close.
                CloseOnServingThread();
                throw new InvalidOperationException("The listener is not started.");
            }

            // Try to get context until service is running.
            HttpListenerContext context = null;
            while (m_ServiceRunning && context == null)
            {
                // Before waiting for event we need to look for pending connections.
                if (m_InputStreamsQueue.Count > 0)
                {
                    OutputNetworkStreamWrapper outputStreamWrap = m_InputStreamsQueue.Dequeue() as OutputNetworkStreamWrapper;
                    if (outputStreamWrap != null)
                    {
                        context = new HttpListenerContext(outputStreamWrap, this);
                    }

                    continue;
                }

                // Cosmos: what the accept thread and the waiting threads do on nanoFramework.
                bool busy = AcceptPendingConnection();
                busy |= CheckHandshakes();
                busy |= CheckWaitingConnections();

                if (!busy && m_InputStreamsQueue.Count == 0)
                {
                    Thread.Sleep(m_Handshaking.Count > 0 ? HandshakeSleepMilliseconds : IdleSleepMilliseconds);
                }
            }

            // Stopped from another thread: the sockets are this thread's to close.
            if (!m_ServiceRunning)
            {
                CloseOnServingThread();
            }

            return context;
        }

        /// <summary>
        /// Gets whether the <itemref>HttpListener</itemref> service was started
        /// and is waiting for client connections.
        /// </summary>
        /// <value><itemref>true</itemref> if the
        /// <itemref>HttpListener</itemref> was started; otherwise,
        /// <itemref>false</itemref>.</value>
        public bool IsListening
        {
            get { return m_ServiceRunning; }
        }

        /// <summary>
        /// Gets or sets the maximum allowed length of the response headers, in
        /// KB.
        /// </summary>
        /// <value>The length, in kilobytes (1024 bytes), of the response
        /// headers.</value>
        /// <remarks>
        /// The length of the response header includes the response status line
        /// and any extra control characters that are received as part of the
        /// HTTP protocol.  A value of -1 means no limit is imposed on the
        /// response headers; a value of 0 means that all requests fail.  If
        /// this property is not explicitly set, it defaults to 4 (KB).
        /// </remarks>
        public int MaximumResponseHeadersLength
        {
            get { return m_maxResponseHeadersLen; }
            set
            {
                if (value <= 0 && value != -1)
                {
#pragma warning disable S3928 // Parameter names used into ArgumentException constructors should match an existing one 
                    throw new ArgumentOutOfRangeException();
#pragma warning restore S3928 // Parameter names used into ArgumentException constructors should match an existing one 
                    // can't add description as that would increase the deployment image size
                }

                m_maxResponseHeadersLen = value;
            }
        }

#pragma warning disable S2292 // Trivial properties should be auto-implemented
        /// <summary>
        /// The certificate used if <see cref="HttpListener"/> implements an https server.
        /// </summary>
        public X509Certificate HttpsCert
#pragma warning restore S2292 // Trivial properties should be auto-implemented
        // nanoFramework doesn't support auto-properties
        {
            get { return m_httpsCert; }
            set { m_httpsCert = value; }
        }
    }
}
