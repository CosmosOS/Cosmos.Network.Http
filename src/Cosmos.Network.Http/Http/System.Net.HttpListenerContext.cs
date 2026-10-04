//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

namespace Cosmos.Network.Http
{
    using System.Net.Sockets;

    /// <summary>
    /// Provides access to the request and response objects used by the
    /// <itemref>HttpListener</itemref> class.  This class cannot be inherited.
    /// </summary>
    public class HttpListenerContext
    {
        /// <summary>
        /// A flag that indicates whether an HTTP request was parsed.
        /// </summary>
        /// <remarks>
        /// The HTTP request is parsed upon the first access to the Request to
        /// Response property.  Access to that property might be done from a
        /// different thread than the thread that is used for construction of
        /// the HttpListenerContext.
        /// </remarks>
        bool m_IsHTTPRequestParsed;

        /// <summary>
        /// Member with network stream connected to client.
        /// This stream is used for writing data.
        /// This stream owns the socket.
        /// </summary>
        internal OutputNetworkStreamWrapper m_clientOutputStream;

        /// <summary>
        /// Member with network stream connected to client.
        /// This stream is used for Reading data.
        /// This stream does not own the socket.
        /// </summary>
        internal InputNetworkStreamWrapper m_clientInputStream;

        /// <summary>
        /// Instance of the request from client.
        /// it is a server side representation of HttpWebRequest.
        /// It is the same data, but instead of composing request we parse it.
        /// </summary>
        private HttpListenerRequest m_ClientRequest;

        /// <summary>
        /// Instance of the response to client.
        ///
        /// </summary>
        internal HttpListenerResponse m_ResponseToClient;

        /// <summary>
        /// Internal constructor, used each time client connects.
        /// </summary>
        /// <param name="clientStream">The stream that is connected to the client. A stream is needed, to
        /// provide information about the connected client.
        /// See also the <see cref="HttpListenerRequest"/> class.
        /// </param>
        /// <param name="httpListener">TBD</param>
        internal HttpListenerContext(OutputNetworkStreamWrapper clientStream, HttpListener httpListener)
        {
            // Saves the stream.
            m_clientOutputStream = clientStream;

            // Input stream does not own socket.
            // Cosmos: the connection's, kept across its requests (OutputNetworkStreamWrapper.m_Input).
            if (clientStream.m_Input == null)
            {
                clientStream.m_Input = new InputNetworkStreamWrapper(clientStream.m_Stream, clientStream.m_Socket, false, null);
            }
            else
            {
                clientStream.m_Input.StartRequest();
            }

            m_clientInputStream = clientStream.m_Input;

            // Constructs request and response classes.
            m_ClientRequest = new HttpListenerRequest(m_clientInputStream, httpListener.m_maxResponseHeadersLen);

            // Closing reponse to client causes removal from clientSocketsList.
            // Thus we need to pass clientSocketsList to client response.
            m_ResponseToClient = new HttpListenerResponse(m_clientOutputStream, httpListener);

            // There is incoming connection HTTP connection. Add new Socket to the list of connected sockets
            // The socket is removed from this array after correponding HttpListenerResponse is closed.
            httpListener.AddClientStream(m_clientOutputStream);

            // Set flag that HTTP request was not parsed yet.
            // It will be parsed on first access to m_ClientRequest or m_ResponseToClient
            m_IsHTTPRequestParsed = false;
        }

        public void Reset()
        {
            m_IsHTTPRequestParsed = false;
            m_ClientRequest.Reset();
        }

        /// <summary>
        /// Gets the <itemref>HttpListenerRequest</itemref> that represents a
        /// client's request for a resource.
        /// </summary>
        /// <value>An <itemref>HttpListenerRequest</itemref> object that
        /// represents the client request.</value>
        public HttpListenerRequest Request
        {
            get
            {
                if (!m_IsHTTPRequestParsed)
                {
                    // Cosmos: parsed once, even when that throws: nanoFramework parsed again on every access after a
                    // failure, from the middle of the request, and the response could never be sent.
                    m_IsHTTPRequestParsed = true;

                    m_ClientRequest.ParseHTTPRequest();
                    // After request parsed check for "transfer-ecoding" header. If it is chunked, change stream property.
                    // If m_EnableChunkedDecoding is set to true, then readig from stream automatically processing chunks.
                    // Cosmos: not after Close, which drops the streams: a null dereference is a kernel panic on Cosmos.
                    string chunkedVal = m_ClientRequest.Headers[HttpKnownHeaderNames.TransferEncoding];
                    if (m_clientInputStream == null)
                    {
                    }
                    else if (chunkedVal != null && chunkedVal.ToLower() == "chunked")
                    {
                        m_clientInputStream.m_EnableChunkedDecoding = true;
                    }
                    else
                    {
                        // Cosmos: the body's length, which bounds reading it, so the next request isn't read as its
                        // end and its Read returns 0 at its end rather than waiting; none without Content-Length, as a
                        // request has no body to end with the connection (RFC 9112, 6.3).
                        m_clientInputStream.m_BytesLeftInResponse = m_ClientRequest.ContentLength64 > 0 ? m_ClientRequest.ContentLength64 : 0;
                    }

                    // Cosmos: for the response, which has no body for a HEAD request.
                    if (m_ResponseToClient != null)
                    {
                        m_ResponseToClient.m_RequestMethod = m_ClientRequest.HttpMethod;
                    }
                }

                return m_ClientRequest;
            }
        }

        /// <summary>
        /// Gets the <itemref>HttpListenerResponse</itemref> object that will be
        /// sent to the client in response to the client's request.
        /// </summary>
        /// <value>An <itemref>HttpListenerResponse</itemref> object used to
        /// send a response back to the client.</value>
        public HttpListenerResponse Response
        {
            get
            {
                if (!m_IsHTTPRequestParsed)
                {
                    // Cosmos: see Request. Its chunked body decoded, which nanoFramework skipped when Response came first.
                    _ = Request;
                }

                return m_ResponseToClient;
            }
        }

        /// <summary>
        /// Get WebsocketContext for WebsocketServer.
        /// This will release all bindings and resources from the HttpListner rendering HttpListnerContext unusable. 
        /// </summary>
        internal WebSocketContext GetWebsocketContext()
        {
            var webSocketContext = new WebSocketContext(m_clientOutputStream.m_Socket, m_clientOutputStream.m_Stream, Request.Headers);

            m_ResponseToClient.m_Listener.RemoveClientStream(m_ResponseToClient.m_clientStream);

            m_ResponseToClient = null;
            m_clientOutputStream = null;
            m_clientInputStream = null;



            return webSocketContext;
        }

        /// <summary>
        /// Closes the stream attached to this listener context. 
        /// </summary>
        public void Close()
        {
            // Cosmos: no DontLinger option, which faults on Cosmos's sockets (see HttpListener.Start); Cosmos's
            // Close doesn't linger past the peer's acknowledgment anyway.
            // Cosmos: each step guarded on its own, where nanoFramework's single try skipped the closing of the
            // connection when the response's Close threw (a client gone).

            bool keptAlive = false;
            if (m_ResponseToClient != null)
            {
                try
                {
                    m_ResponseToClient.Close();
                }
                catch
                {
                }

                // Cosmos: a connection kept alive is the listener's now, waiting for its next request: nanoFramework
                // closed it here, after the response had put it on the waiting list.
                keptAlive = m_ResponseToClient.m_KeptAlive;
                m_ResponseToClient = null;
            }

            if (keptAlive)
            {
                m_clientOutputStream = null;
                m_clientInputStream = null;
                return;
            }

            // Close the underlying stream
            if (m_clientOutputStream != null)
            {
                try
                {
                    m_clientOutputStream.Dispose();
                }
                catch
                {
                }

                m_clientOutputStream = null;
            }

            if (m_clientInputStream != null)
            {
                try
                {
                    m_clientInputStream.Dispose();
                }
                catch
                {
                }

                m_clientInputStream = null;
            }
        }
    }
}
