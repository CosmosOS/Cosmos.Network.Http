// Cosmos: tests of SslStream over loopback, client and server, as the port's TLS is managed code where nanoFramework's
// is native (its tests have none).

using System;
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
    public class SslStreamTests
    {
        private const int Timeout = 20_000;

        /// <summary>
        /// A TLS server for one connection on a thread of its own, which echoes what it reads until the client closes.
        /// </summary>
        private sealed class EchoServer : IDisposable
        {
            private readonly Socket _listener;
            private readonly Thread _thread;

            internal EchoServer(X509Certificate certificate, SslProtocols protocols, SslVerification verification, X509Certificate ca = null)
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
                        using var stream = new SslStream(socket) { SslVerification = verification };
                        stream.ReadTimeout = Timeout;
                        stream.Authenticate(true, null, certificate, ca, protocols);

                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            stream.Write(buffer, 0, read);
                        }
                    }
                    catch (Exception e)
                    {
                        Error = e;
                    }
                });
                _thread.IsBackground = true;
                _thread.Start();
            }

            internal int Port { get; }

            internal Exception Error { get; private set; }

            internal void Join() => Assert.IsTrue(_thread.Join(Timeout), "The server didn't finish.");

            public void Dispose()
            {
                _listener.Close();
                _thread.Join(Timeout);
            }
        }

        private static SslStream Connect(EchoServer server, string host, SslProtocols protocols, X509Certificate ca, SslVerification verification = SslVerification.CertificateRequired, X509Certificate clientCertificate = null)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(new IPEndPoint(IPAddress.Loopback, server.Port));

            var stream = new SslStream(socket) { SslVerification = verification };
            stream.ReadTimeout = Timeout;
            try
            {
                stream.AuthenticateAsClient(host, clientCertificate, ca, protocols);
            }
            catch
            {
                // So the server's handshake ends too.
                socket.Close();
                throw;
            }

            return stream;
        }

        private static void AssertEcho(SslStream stream, int size)
        {
            byte[] sent = new byte[size];
            new Random(size).NextBytes(sent);

            stream.Write(sent, 0, sent.Length);

            byte[] received = new byte[size];
            int total = 0;
            while (total < size)
            {
                int read = stream.Read(received, total, size - total);
                Assert.IsTrue(read > 0, "The connection closed after " + total + " of " + size + " bytes.");
                total += read;
            }

            CollectionAssert.AreEqual(sent, received);
        }

        [DataTestMethod]
        [DataRow(SslProtocols.Tls13, false)]
        [DataRow(SslProtocols.Tls13, true)]
        [DataRow(SslProtocols.Tls12, false)]
        [DataRow(SslProtocols.Tls12, true)]
        [DataRow(SslProtocols.None, false)]
        public void Handshake_AndEcho(SslProtocols protocols, bool rsa)
        {
            TestCertificate certificate = rsa ? TestCertificates.RsaServer : TestCertificates.EcServer;

            using var server = new EchoServer(certificate.WithKey(), protocols, SslVerification.NoVerification);
            using (SslStream client = Connect(server, "localhost", protocols, TestCertificates.Root.Public()))
            {
                AssertEcho(client, 11);
                AssertEcho(client, 70_000);
            }

            server.Join();
            Assert.IsNull(server.Error, server.Error?.ToString());
        }

        [TestMethod]
        public void Handshake_ByIpAddress()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);
            using (SslStream client = Connect(server, "127.0.0.1", SslProtocols.Tls13, TestCertificates.Root.Public()))
            {
                AssertEcho(client, 100);
            }

            server.Join();
        }

        [TestMethod]
        public void Handshake_TrustedThroughCertificateManager()
        {
            try
            {
                Assert.IsTrue(CertificateManager.AddCaCertificateBundle(new[] { TestCertificates.Root.Public() }));

                using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls12, SslVerification.NoVerification);
                using (SslStream client = Connect(server, "localhost", SslProtocols.Tls12, null))
                {
                    AssertEcho(client, 100);
                }

                server.Join();
            }
            finally
            {
                // The embedded roots again.
                using Stream roots = typeof(CertificateManager).Assembly.GetManifestResourceStream("Cosmos.Network.Http.cacert.pem");
                var pem = new MemoryStream();
                roots.CopyTo(pem);
                Assert.IsTrue(CertificateManager.AddCaCertificateBundle(pem.ToArray()));
            }
        }

        [DataTestMethod]
        [DataRow(SslProtocols.Tls13)]
        [DataRow(SslProtocols.Tls12)]
        public void Handshake_WrongHost_Fails(SslProtocols protocols)
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), protocols, SslVerification.NoVerification);

            var error = Assert.ThrowsException<AuthenticationException>(() => Connect(server, "example.com", protocols, TestCertificates.Root.Public()));
            StringAssert.Contains(error.Message, "example.com");
        }

        [TestMethod]
        public void Handshake_UntrustedServer_Fails()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);

            Assert.ThrowsException<AuthenticationException>(() => Connect(server, "localhost", SslProtocols.Tls13, TestCertificates.OtherRoot.Public()));
        }

        [TestMethod]
        public void Handshake_UntrustedServer_NoVerification_Succeeds()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);
            using (SslStream client = Connect(server, "example.com", SslProtocols.Tls13, TestCertificates.OtherRoot.Public(), SslVerification.NoVerification))
            {
                AssertEcho(client, 100);
            }

            server.Join();
        }

        [TestMethod]
        public void Handshake_NoCommonVersion_Fails()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);

            Assert.ThrowsException<AuthenticationException>(() => Connect(server, "localhost", SslProtocols.Tls12, TestCertificates.Root.Public()));
        }

        [TestMethod]
        public void Handshake_UnsupportedProtocol_Throws()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);

#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete: refused here.
            Assert.ThrowsException<NotSupportedException>(() => Connect(server, "localhost", SslProtocols.Tls11, TestCertificates.Root.Public()));
#pragma warning restore SYSLIB0039
        }

        [DataTestMethod]
        [DataRow(SslProtocols.Tls13)]
        [DataRow(SslProtocols.Tls12)]
        public void ClientCertificate_Required_Succeeds(SslProtocols protocols)
        {
            using var server = new EchoServer(TestCertificates.RsaServer.WithKey(), protocols, SslVerification.CertificateRequired, TestCertificates.Root.Public());
            using (SslStream client = Connect(server, "localhost", protocols, TestCertificates.Root.Public(), clientCertificate: TestCertificates.Client.WithKey()))
            {
                AssertEcho(client, 100);
            }

            server.Join();
            Assert.IsNull(server.Error, server.Error?.ToString());
        }

        [DataTestMethod]
        [DataRow(SslProtocols.Tls13)]
        [DataRow(SslProtocols.Tls12)]
        public void ClientCertificate_Missing_Fails(SslProtocols protocols)
        {
            using var server = new EchoServer(TestCertificates.RsaServer.WithKey(), protocols, SslVerification.CertificateRequired, TestCertificates.Root.Public());

            try
            {
                // In TLS 1.3 the client may finish its handshake before the server refuses it: the refusal comes with
                // the first read.
                using SslStream client = Connect(server, "localhost", protocols, TestCertificates.Root.Public());
                byte[] buffer = new byte[1];
                client.Write(buffer, 0, 1);
                client.Read(buffer, 0, 1);
                Assert.Fail("The server accepted a client without a certificate.");
            }
            catch (AuthenticationException)
            {
            }
            catch (IOException)
            {
            }

            server.Join();
            Assert.IsInstanceOfType(server.Error, typeof(AuthenticationException));
        }

        [TestMethod]
        public void ServerCertificate_WithoutKey_Throws()
        {
            var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);
            var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(listener.LocalEndPoint);
            Socket socket = listener.Accept();

            var stream = new SslStream(socket);

            Assert.ThrowsException<AuthenticationException>(() => stream.Authenticate(true, null, TestCertificates.RsaServer.Public(), null, SslProtocols.Tls12));

            socket.Close();
            client.Close();
            listener.Close();
        }

        [TestMethod]
        public void Read_PeerClosed_ReturnsZero()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);
            using SslStream client = Connect(server, "localhost", SslProtocols.Tls13, TestCertificates.Root.Public());

            AssertEcho(client, 10);

            // The server's echo loop ends when its Read returns 0, without an exception.
            client.Close();
            server.Join();
            Assert.IsNull(server.Error, server.Error?.ToString());
        }

        [TestMethod]
        public void Read_Timeout_Throws()
        {
            var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            // A server that accepts and never answers the ClientHello.
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(listener.LocalEndPoint);
            Socket accepted = listener.Accept();

            var stream = new SslStream(socket);
            stream.ReadTimeout = 300;

            Assert.ThrowsException<IOException>(() => stream.AuthenticateAsClient("localhost", SslProtocols.Tls13));

            accepted.Close();
            listener.Close();
            socket.Close();
        }

        [TestMethod]
        public void DataAvailable_AfterServerWrites()
        {
            using var server = new EchoServer(TestCertificates.EcServer.WithKey(), SslProtocols.Tls13, SslVerification.NoVerification);
            using SslStream client = Connect(server, "localhost", SslProtocols.Tls13, TestCertificates.Root.Public());

            byte[] data = Encoding.ASCII.GetBytes("ping");
            client.Write(data, 0, data.Length);

            long start = Environment.TickCount64;
            while (!client.DataAvailable)
            {
                Assert.IsTrue(Environment.TickCount64 - start < Timeout, "No data became available.");
                Thread.Sleep(5);
            }

            Assert.IsTrue(client.Length > 0);

            byte[] buffer = new byte[16];
            int read = client.Read(buffer, 0, buffer.Length);
            Assert.AreEqual("ping", Encoding.ASCII.GetString(buffer, 0, read));
        }
    }
}
