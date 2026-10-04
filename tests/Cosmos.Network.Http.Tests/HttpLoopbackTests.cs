// Cosmos: HttpClient against HttpListener over loopback, http and https. nanoFramework's tests skip HttpClient's
// (its desktop CLR has no network) and have none of HttpListener's serving.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cosmos.Network.Http.Tests
{
    [TestClass]
    public class HttpLoopbackTests
    {
        private static readonly byte[] s_big = CreateBig(1024 * 1024 + 123);

        /// <summary>
        /// An HttpListener served by one thread, as AuraOS serves it.
        /// </summary>
        private sealed class TestServer : IDisposable
        {
            private readonly HttpListener _listener;
            private readonly Thread _thread;
            private readonly List<Exception> _errors = new List<Exception>();
            private int _taken;
            private int _handled;

            internal TestServer(bool https = false, SslProtocols protocols = SslProtocols.Tls12)
            {
                Port = FreePort();
                _listener = new HttpListener(https ? "https" : "http", Port);
                if (https)
                {
                    _listener.HttpsCert = TestCertificates.EcServer.WithKey();
                    _listener.SslProtocols = protocols;
                }

                _listener.Start();

                _thread = new Thread(Serve) { IsBackground = true };
                _thread.Start();
            }

            internal int Port { get; }

            internal List<int> ClientPorts { get; } = new List<int>();

            internal string Url(string path) => (_listener.HttpsCert != null ? "https" : "http") + "://localhost:" + Port + path;

            internal void Stop() => _listener.Stop();

            internal void Start() => _listener.Start();

            private void Serve()
            {
                while (_listener.IsListening)
                {
                    HttpListenerContext context = _listener.GetContext();
                    if (context == null)
                    {
                        break;
                    }

                    Interlocked.Increment(ref _taken);
                    try
                    {
                        lock (ClientPorts)
                        {
                            ClientPorts.Add(context.Request.RemoteEndPoint.Port);
                        }

                        Handle(context);
                    }
                    catch (Exception e)
                    {
                        lock (_errors)
                        {
                            _errors.Add(e);
                        }
                    }

                    Interlocked.Increment(ref _handled);
                }

                // As AuraOS's httpd: the sockets are the serving thread's to close.
                _listener.Close();
            }

            private static void Handle(HttpListenerContext context)
            {
                HttpListenerRequest request = context.Request;
                HttpListenerResponse response = context.Response;

                // nanoFramework's responses close the connection unless told otherwise.
                response.KeepAlive = request.KeepAlive;

                switch (request.RawUrl)
                {
                    case "/hello":
                        Respond(response, Encoding.UTF8.GetBytes("Hello, Cosmos"));
                        break;

                    case "/echo":
                    {
                        var body = new MemoryStream();
                        byte[] buffer = new byte[4096];
                        long left = request.ContentLength64;
                        while (left > 0)
                        {
                            int read = request.InputStream.Read(buffer, 0, (int)Math.Min(buffer.Length, left));
                            if (read <= 0)
                            {
                                break;
                            }

                            body.Write(buffer, 0, read);
                            left -= read;
                        }

                        response.ContentType = request.ContentType;
                        Respond(response, body.ToArray());
                        break;
                    }

                    case "/big":
                        Respond(response, s_big);
                        break;

                    case "/chunked":
                    {
                        response.SendChunked = true;
                        for (int i = 0; i < 5; i++)
                        {
                            byte[] part = Encoding.ASCII.GetBytes("part" + i + ";");
                            response.OutputStream.Write(part, 0, part.Length);
                        }

                        response.Close();
                        break;
                    }

                    case "/header":
                        response.Headers.Add("X-Echo", request.Headers["X-Test"]);
                        Respond(response, Array.Empty<byte>());
                        break;

                    case "/postnoread":
                        // Answered without reading the body.
                        response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                        Respond(response, Encoding.UTF8.GetBytes("no"));
                        break;

                    case "/headchunked":
                    {
                        response.SendChunked = true;
                        if (request.HttpMethod != "HEAD")
                        {
                            byte[] part = Encoding.ASCII.GetBytes("chunk");
                            response.OutputStream.Write(part, 0, part.Length);
                        }

                        response.Close();
                        break;
                    }

                    case "/short":
                    {
                        // Says 100 bytes, sends 10.
                        response.ContentLength64 = 100;
                        byte[] part = new byte[10];
                        response.OutputStream.Write(part, 0, part.Length);
                        response.Close();
                        break;
                    }

                    case "/unframed":
                    {
                        // Neither sized nor chunked: ends with the connection.
                        byte[] part = Encoding.ASCII.GetBytes("unframed body");
                        response.OutputStream.Write(part, 0, part.Length);
                        response.Close();
                        break;
                    }

                    case "/ua":
                        Respond(response, Encoding.UTF8.GetBytes(request.UserAgent ?? "(none)"));
                        break;

                    case "/host":
                        Respond(response, Encoding.UTF8.GetBytes(request.Headers["Host"] + "|" + request.UserHostName));
                        break;

                    case "/head":
                        // The length of the body a GET would have, which a HEAD response announces without sending.
                        response.ContentLength64 = s_big.Length;
                        if (request.HttpMethod != "HEAD")
                        {
                            response.OutputStream.Write(s_big, 0, s_big.Length);
                        }

                        response.Close();
                        break;

                    case "/nocontent":
                        response.StatusCode = (int)HttpStatusCode.NoContent;
                        response.Close();
                        break;

                    case "/closeoutput":
                    {
                        // The output stream closed by the handler, then the response and the context.
                        byte[] body = Encoding.UTF8.GetBytes("closed output");
                        response.ContentLength64 = body.Length;
                        using (Stream output = response.OutputStream)
                        {
                            output.Write(body, 0, body.Length);
                        }

                        response.Close();
                        context.Close();
                        break;
                    }

                    case "/ctxclose":
                        Respond(response, Encoding.UTF8.GetBytes("Hello, Cosmos"));
                        context.Close();
                        break;

                    case "/slow":
                        Thread.Sleep(3000);
                        Respond(response, Encoding.UTF8.GetBytes("late"));
                        break;

                    default:
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                        Respond(response, Encoding.UTF8.GetBytes("Not found"));
                        break;
                }

                // Not context.Close(), which would close a kept-alive connection: the response's Close closes it
                // unless it is kept alive.
            }

            private static void Respond(HttpListenerResponse response, byte[] body)
            {
                response.ContentLength64 = body.Length;
                response.OutputStream.Write(body, 0, body.Length);
                response.Close();
            }

            internal void AssertNoError()
            {
                // The requests the server took handled to their end: a client has its response before the response's
                // Close returns.
                long start = Environment.TickCount64;
                while (Volatile.Read(ref _handled) != Volatile.Read(ref _taken) && Environment.TickCount64 - start < 5000)
                {
                    Thread.Sleep(10);
                }

                lock (_errors)
                {
                    Assert.AreEqual(0, _errors.Count, _errors.Count > 0 ? _errors[0].ToString() : null);
                }
            }

            public void Dispose()
            {
                try
                {
                    _listener.Stop();
                }
                catch (ObjectDisposedException)
                {
                    // Stopped and closed by the serving thread already.
                }

                Assert.IsTrue(_thread.Join(10_000), "GetContext didn't return after Stop.");
            }
        }

        /// <summary>
        /// A server that answers one connection with raw bytes, then closes it.
        /// </summary>
        private sealed class RawServer : IDisposable
        {
            private readonly Socket _listener;
            private readonly Thread _thread;

            internal RawServer(string response)
            {
                _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                _listener.Listen(1);
                Port = ((IPEndPoint)_listener.LocalEndPoint).Port;

                _thread = new Thread(() =>
                {
                    try
                    {
                        using Socket socket = _listener.Accept();

                        // The request's head.
                        var head = new StringBuilder();
                        byte[] buffer = new byte[1];
                        while (!head.ToString().EndsWith("\r\n\r\n") && socket.Receive(buffer) == 1)
                        {
                            head.Append((char)buffer[0]);
                        }

                        socket.Send(Encoding.ASCII.GetBytes(response));
                        socket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    {
                    }
                })
                { IsBackground = true };
                _thread.Start();
            }

            internal int Port { get; }

            public void Dispose()
            {
                _listener.Close();
                _thread.Join(5000);
            }
        }

        private static int FreePort()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)socket.LocalEndPoint).Port;
            socket.Close();
            return port;
        }

        private static byte[] CreateBig(int size)
        {
            byte[] data = new byte[size];
            new Random(42).NextBytes(data);
            return data;
        }

        private static HttpClient CreateClient(SslProtocols protocols = SslProtocols.Tls12)
        {
            return new HttpClient
            {
                HttpsAuthentCert = TestCertificates.Root.Public(),
                SslProtocols = protocols,
                Timeout = TimeSpan.FromSeconds(20),
            };
        }

        [DataTestMethod]
        [DataRow(false, SslProtocols.Tls12)]
        [DataRow(true, SslProtocols.Tls12)]
        [DataRow(true, SslProtocols.Tls13)]
        public void GetString(bool https, SslProtocols protocols)
        {
            using var server = new TestServer(https, protocols);
            using HttpClient client = CreateClient(protocols);

            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void GetByteArray_Big(bool https)
        {
            using var server = new TestServer(https);
            using HttpClient client = CreateClient();

            CollectionAssert.AreEqual(s_big, client.GetByteArray(server.Url("/big")));

            server.AssertNoError();
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void GetStream_Big(bool https)
        {
            using var server = new TestServer(https);
            using HttpClient client = CreateClient();

            using Stream stream = client.GetStream(server.Url("/big"));
            var read = new MemoryStream();
            stream.CopyTo(read);
            CollectionAssert.AreEqual(s_big, read.ToArray());

            server.AssertNoError();
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void ResponseHeadersRead_Big(bool https)
        {
            using var server = new TestServer(https);
            using HttpClient client = CreateClient();

            using HttpResponseMessage response = client.Get(server.Url("/big"), HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var received = new MemoryStream();
            response.Content.ReadAsStream().CopyTo(received);
            CollectionAssert.AreEqual(s_big, received.ToArray());

            server.AssertNoError();
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void Post_Echo(bool https)
        {
            using var server = new TestServer(https);
            using HttpClient client = CreateClient();

            string body = new string('x', 50_000) + "end";
            using HttpResponseMessage response = client.Post(server.Url("/echo"), new StringContent(body, Encoding.UTF8, "text/plain"));

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(body, response.Content.ReadAsString());

            server.AssertNoError();
        }

        [TestMethod]
        public void Get_Chunked()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();

            Assert.AreEqual("part0;part1;part2;part3;part4;", client.GetString(server.Url("/chunked")));

            server.AssertNoError();
        }

        [TestMethod]
        public void Get_NotFound()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();

            using (HttpResponseMessage response = client.Get(server.Url("/missing")))
            {
                Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
                Assert.AreEqual("Not Found", response.ReasonPhrase);
                Assert.AreEqual("Not found", response.Content.ReadAsString());
            }

            Assert.ThrowsException<HttpRequestException>(() => client.GetString(server.Url("/missing")));

            server.AssertNoError();
        }

        [TestMethod]
        public void Headers_RoundTrip()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.Add("X-Test", "cosmos");

            using HttpResponseMessage response = client.Get(server.Url("/header"));

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsTrue(response.Headers.TryGetValues("X-Echo", out IEnumerable<string> values));
            CollectionAssert.AreEqual(new[] { "cosmos" }, new List<string>(values));
            Assert.IsTrue(response.Headers.Contains("x-echo"));
            Assert.IsFalse(response.Headers.Contains("X-Missing"));
            Assert.ThrowsException<InvalidOperationException>(() => response.Headers.GetValues("X-Missing"));

            server.AssertNoError();
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void KeepAlive_ReusesTheConnection(bool https)
        {
            using var server = new TestServer(https);
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            for (int i = 0; i < 3; i++)
            {
                Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            }

            CollectionAssert.AreEqual(s_big, client.GetByteArray(server.Url("/big")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
            Assert.AreEqual(5, server.ClientPorts.Count);
            Assert.AreEqual(1, new HashSet<int>(server.ClientPorts).Count, "The requests came over several connections: " + string.Join(", ", server.ClientPorts));
        }

        [TestMethod]
        public void ConnectionClose_OpensOnePerRequest()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();

            for (int i = 0; i < 3; i++)
            {
                Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            }

            server.AssertNoError();
            Assert.AreEqual(3, new HashSet<int>(server.ClientPorts).Count);
        }

        [TestMethod]
        public void Timeout_Throws()
        {
            using var server = new TestServer();
            using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };

            Assert.ThrowsException<HttpRequestException>(() => client.GetString(server.Url("/slow")));
        }

        [TestMethod]
        public void Https_Untrusted_Throws()
        {
            using var server = new TestServer(https: true);
            using var client = new HttpClient { HttpsAuthentCert = TestCertificates.OtherRoot.Public() };

            Exception error = null;
            try
            {
                client.GetString(server.Url("/hello"));
            }
            catch (Exception e)
            {
                error = e;
            }

            Assert.IsNotNull(error, "The request succeeded with an untrusted server.");
            Assert.IsTrue(error is HttpRequestException || error is AuthenticationException || error is WebException, error.ToString());
        }

        [TestMethod]
        public void ConnectionRefused_Throws()
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

            Assert.ThrowsException<HttpRequestException>(() => client.GetString("http://127.0.0.1:" + FreePort() + "/"));
        }

        [DataTestMethod]
        [DataRow("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")]
        [DataRow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")]
        [DataRow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nhello")]
        public void Response_CutShort_Throws(string raw)
        {
            using var server = new RawServer(raw);
            using HttpClient client = CreateClient();

            Assert.ThrowsException<HttpRequestException>(() => client.GetString("http://127.0.0.1:" + server.Port + "/"));
        }

        [DataTestMethod]
        [DataRow("\r\n\r\n")]
        [DataRow("ICY 200 OK\r\n\r\n")]
        [DataRow("HTTP/1.1 OK\r\n\r\n")]
        [DataRow("SSH-2.0-OpenSSH_9.6\r\n")]
        public void Response_Malformed_Throws(string raw)
        {
            using var server = new RawServer(raw);
            using HttpClient client = CreateClient();

            Assert.ThrowsException<HttpRequestException>(() => client.GetString("http://127.0.0.1:" + server.Port + "/"));
        }

        [TestMethod]
        public void Response_CloseDelimited_IsComplete()
        {
            // An HTTP/1.0 body that ends with the connection, after more than the read buffer holds.
            string body = new string('b', 1000) + "end";
            using var server = new RawServer("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body);
            using HttpClient client = CreateClient();

            Assert.AreEqual(body, client.GetString("http://127.0.0.1:" + server.Port + "/"));
        }

        [TestMethod]
        public void KeepAlive_RequestBodyLeftUnread_ClosesTheConnection()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            using (HttpResponseMessage response = client.Post(server.Url("/postnoread"), new StringContent(new string('p', 5000))))
            {
                Assert.AreEqual(HttpStatusCode.MethodNotAllowed, response.StatusCode);
                Assert.IsTrue(response.Headers.TryGetValues("Connection", out IEnumerable<string> connection));
                CollectionAssert.AreEqual(new[] { "Close" }, new List<string>(connection));
            }

            // Not read as a request: the next one gets its own answer.
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
            Assert.AreEqual(2, new HashSet<int>(server.ClientPorts).Count, "The connection the body was left on was reused: " + string.Join(", ", server.ClientPorts));
        }

        [TestMethod]
        public void KeepAlive_HeadOfChunkedResponse_HasNoChunk()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            using (HttpResponseMessage response = client.Send(new HttpRequestMessage(HttpMethod.Head, server.Url("/headchunked"))))
            {
                Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            }

            Assert.AreEqual("chunk", client.GetString(server.Url("/headchunked")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
            Assert.AreEqual(1, new HashSet<int>(server.ClientPorts).Count);
        }

        [TestMethod]
        public void Response_ShorterThanItsLength_ClosesTheConnection()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            Assert.ThrowsException<HttpRequestException>(() => client.GetString(server.Url("/short")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
        }

        [TestMethod]
        public void Response_Unframed_EndsWithTheConnection()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            Assert.AreEqual("unframed body", client.GetString(server.Url("/unframed")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
        }

        [TestMethod]
        public void UserAgent_CanBeSet()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.Add("User-Agent", "AuraOS/test");

            Assert.AreEqual("AuraOS/test", client.GetString(server.Url("/ua")));

            // Those the request sets itself stay refused.
            Assert.ThrowsException<ArgumentException>(() => client.DefaultRequestHeaders.Add("Host", "example.com"));
            Assert.ThrowsException<ArgumentException>(() => client.DefaultRequestHeaders.Add("Content-Length", "1"));
        }

        [TestMethod]
        public void Host_IncludesPort()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();

            Assert.AreEqual("localhost:" + server.Port + "|localhost:" + server.Port, client.GetString(server.Url("/host")));
        }

        [TestMethod]
        public void Head_OnKeptAliveConnection_DoesNotWait()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;
            client.Timeout = TimeSpan.FromSeconds(5);

            long start = Environment.TickCount64;
            using (HttpResponseMessage response = client.Send(new HttpRequestMessage(HttpMethod.Head, server.Url("/head"))))
            {
                Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
                Assert.AreEqual(0, response.Content.ReadAsByteArray().Length);
            }

            using (HttpResponseMessage response = client.Get(server.Url("/nocontent")))
            {
                Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
            }

            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            Assert.IsTrue(Environment.TickCount64 - start < 3000, "Took " + (Environment.TickCount64 - start) + " ms.");

            server.AssertNoError();
            Assert.AreEqual(1, new HashSet<int>(server.ClientPorts).Count, "The connection wasn't reused.");
        }

        [TestMethod]
        public void OutputStream_ClosedByHandler()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            Assert.AreEqual("closed output", client.GetString(server.Url("/closeoutput")));
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            server.AssertNoError();
        }

        [TestMethod]
        public void ContextClose_KeepsAliveConnection()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            client.DefaultRequestHeaders.ConnectionClose = false;

            for (int i = 0; i < 3; i++)
            {
                Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/ctxclose")));
            }

            server.AssertNoError();
            Assert.AreEqual(1, new HashSet<int>(server.ClientPorts).Count, "The requests came over several connections.");
        }

        [TestMethod]
        public void Pool_DoesNotLendATlsConnectionTrustedOtherwise()
        {
            using var server = new TestServer(https: true);

            using HttpClient trusting = CreateClient();
            trusting.DefaultRequestHeaders.ConnectionClose = false;
            Assert.AreEqual("Hello, Cosmos", trusting.GetString(server.Url("/hello")));

            // The kept-alive connection was authenticated with the test root, which this client doesn't trust.
            using var other = new HttpClient { HttpsAuthentCert = TestCertificates.OtherRoot.Public(), SslProtocols = SslProtocols.Tls12 };
            other.DefaultRequestHeaders.ConnectionClose = false;
            Assert.ThrowsException<HttpRequestException>(() => other.GetString(server.Url("/hello")));
        }

        [TestMethod]
        public void Https_SilentClient_DoesNotHoldTheListener()
        {
            using var server = new TestServer(https: true);

            // A client that connects and never says hello.
            using var silent = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            silent.Connect(new IPEndPoint(IPAddress.Loopback, server.Port));
            Thread.Sleep(200);

            long start = Environment.TickCount64;
            using HttpClient client = CreateClient();
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            Assert.IsTrue(Environment.TickCount64 - start < 3000, "Took " + (Environment.TickCount64 - start) + " ms.");

            server.AssertNoError();
        }

        [TestMethod]
        public void Listener_StopDuringRequest_AnswersItThenCloses()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();

            string answer = null;
            var request = new Thread(() => answer = client.GetString(server.Url("/slow")));
            request.Start();

            // Stopped from this thread while the server's handles the request.
            Thread.Sleep(1000);
            server.Stop();

            Assert.IsTrue(request.Join(10_000));
            Assert.AreEqual("late", answer);
            server.AssertNoError();

            // Closed by the serving thread once the request was answered.
            long start = Environment.TickCount64;
            while (true)
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    probe.Connect(new IPEndPoint(IPAddress.Loopback, server.Port));
                }
                catch (SocketException)
                {
                    break;
                }

                Assert.IsTrue(Environment.TickCount64 - start < 5000, "The listening socket stayed open.");
                Thread.Sleep(50);
            }
        }

        [TestMethod]
        public void Listener_StopThenStart_KeepsServing()
        {
            using var server = new TestServer();
            using HttpClient client = CreateClient();
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));

            // From this thread, before the serving one acts on the Stop: undone.
            server.Stop();
            server.Start();

            Thread.Sleep(200);
            Assert.AreEqual("Hello, Cosmos", client.GetString(server.Url("/hello")));
            server.AssertNoError();
        }

        [TestMethod]
        public void Listener_StopWhileIdle_ReturnsNull()
        {
            int port = FreePort();
            var listener = new HttpListener("http", port);
            listener.Start();

            HttpListenerContext context = null;
            var thread = new Thread(() => context = listener.GetContext());
            thread.Start();

            Thread.Sleep(200);
            listener.Stop();

            Assert.IsTrue(thread.Join(5000));
            Assert.IsNull(context);
            Assert.IsFalse(listener.IsListening);

            // It listens again.
            listener.Start();
            listener.Close();
        }
    }
}
