// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using NUnit.Framework;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// Sends https:// requests to a loopback server that speaks TLS through the
/// desktop's SslStream, with certificates from <see cref="TestPki"/>.
/// </summary>
[TestFixture]
public class HttpsTests
{
    private const int Timeout = 5000;

    private X509Certificate2 _root = null!;
    private X509Certificate2 _intermediate = null!;
    private TrustedRoots _roots = null!;

    [OneTimeSetUp]
    public void CreatePki()
    {
        _root = TestPki.Root();
        _intermediate = TestPki.Authority(_root);
        _roots = TrustedRoots.FromCertificates([_root.RawData]);
    }

    [TestCase(SslProtocols.Tls13)]
    [TestCase(SslProtocols.Tls12)]
    public void Get_OverTls_ReturnsTheBody(SslProtocols protocol)
    {
        using TestServer server = Server(protocol);
        server.Then("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret");

        HttpResponse response = Request(server.Url("/page")).Send();

        Assert.That(response.StatusCode, Is.EqualTo(200));
        Assert.That(response.GetString(), Is.EqualTo("secret"));
        Assert.That(response.Url, Is.EqualTo(server.Url("/page")));

        TestHandshake handshake = server.Handshakes.Single();
        Assert.That(handshake.Protocol, Is.EqualTo(protocol));
        Assert.That(handshake.ApplicationProtocol, Is.EqualTo("http/1.1"));
        Assert.That(server.Requests.Single().Headers["Host"], Is.EqualTo($"127.0.0.1:{server.Port}"));
    }

    [Test]
    public void HostName_IsSentAsServerName()
    {
        using TestServer server = Server();
        server.Then("HTTP/1.1 204 No Content\r\n\r\n");

        Request(server.Url("/", "localhost")).Send();

        Assert.That(server.Handshakes.Single().ServerName, Is.EqualTo("localhost"));
    }

    [Test]
    public void Address_IsNotSentAsServerName()
    {
        using TestServer server = Server();
        server.Then("HTTP/1.1 204 No Content\r\n\r\n");

        Request(server.Url("/")).Send();

        Assert.That(server.Handshakes.Single().ServerName, Is.Null);
    }

    [Test]
    public void Chunked_SentByteByByte_ComesWhole()
    {
        using TestServer server = Server();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.WriteSlowly("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
            connection.WaitForClientClose();
        });

        Assert.That(Request(server.Url("/")).Send().GetString(), Is.EqualTo("abcde"));
    }

    [Test]
    public void LargeBody_SpansManyRecords()
    {
        byte[] body = new byte[200_000];
        new Random(1).NextBytes(body);
        using TestServer server = Server();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n");
            connection.Write(body);
        });

        Assert.That(Request(server.Url("/")).Send().Content, Is.EqualTo(body));
    }

    [Test]
    public void NoLength_EndsAtCloseNotify_WithoutWaitingForTheConnectionToClose()
    {
        using ManualResetEventSlim done = new();
        using TestServer server = Server();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\n\r\nuntil close_notify");
            connection.CloseNotify();
            // The connection stays open, unread: only close_notify ends the body.
            done.Wait(10_000);
        });

        Stopwatch watch = Stopwatch.StartNew();
        HttpResponse response = Request(server.Url("/")).Send();
        long elapsed = watch.ElapsedMilliseconds;
        done.Set();

        Assert.That(response.GetString(), Is.EqualTo("until close_notify"));
        Assert.That(elapsed, Is.LessThan(Timeout / 2));
    }

    [TestCase(SslProtocols.Tls13)]
    [TestCase(SslProtocols.Tls12)]
    public void RsaServer_IsTrusted(SslProtocols protocol)
    {
        X509Certificate2 root = TestPki.Root("RSA Root", RSA.Create(2048));
        X509Certificate2 intermediate = TestPki.Authority(root, "RSA Intermediate", key: RSA.Create(2048));
        X509Certificate2 certificate = TestPki.Server(intermediate, ["127.0.0.1"], key: RSA.Create(2048));
        using TestServer server = new(SslStreamCertificateContext.Create(certificate, [intermediate], offline: true), protocol);
        server.Then("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nrsa");

        HttpResponse response = new HttpRequest(server.Url("/"))
        {
            Timeout = Timeout,
            TrustedRoots = TrustedRoots.FromCertificates([root.RawData]),
        }.Send();

        Assert.That(response.GetString(), Is.EqualTo("rsa"));
        Assert.That(server.Handshakes.Single().Protocol, Is.EqualTo(protocol));
    }

    [Test]
    public void NoLength_ReadsUntilTheServerCloses_WithoutCloseNotify()
    {
        using TestServer server = Server();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\n\r\nuntil the end");
        });

        Assert.That(Request(server.Url("/")).Send().GetString(), Is.EqualTo("until the end"));
    }

    [Test]
    public void ContentLength_CutShort_Throws()
    {
        using TestServer server = Server();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf");
            connection.CloseNotify();
        });

        HttpException exception = Assert.Throws<HttpException>(() => Request(server.Url("/")).Send())!;
        Assert.That(exception.Message, Does.Contain("after 4 of 10 bytes"));
    }

    [Test]
    public void Post_SendsTheBodyEncrypted()
    {
        using TestServer server = Server();
        server.Then("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

        HttpResponse response = new HttpRequest(server.Url("/items"))
        {
            Method = "POST",
            Body = "name=value"u8.ToArray(),
            Timeout = Timeout,
            TrustedRoots = _roots,
        }.Send();

        Assert.That(response.StatusCode, Is.EqualTo(201));
        Assert.That(server.Requests.Single().Body, Is.EqualTo("name=value"u8.ToArray()));
    }

    [Test]
    public void RedirectFromHttp_IsFollowed()
    {
        using TestServer secure = Server();
        secure.Then("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        using TestServer plain = new();
        plain.Then($"HTTP/1.1 301 Moved Permanently\r\nLocation: {secure.Url("/")}\r\nContent-Length: 0\r\n\r\n");

        HttpResponse response = Request(plain.Url("/")).Send();

        Assert.That(response.GetString(), Is.EqualTo("ok"));
        Assert.That(response.Url, Is.EqualTo(secure.Url("/")));
    }

    [Test]
    public void RedirectToHttp_IsNotFollowed()
    {
        using TestServer plain = new();
        using TestServer secure = Server();
        secure.Then($"HTTP/1.1 307 Temporary Redirect\r\nLocation: {plain.Url("/leak")}\r\nContent-Length: 0\r\n\r\n");

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(secure.Url("/"))
        {
            Method = "POST",
            Body = "password=hunter2"u8.ToArray(),
            Headers = { ["Authorization"] = "Bearer secret" },
            Timeout = Timeout,
            TrustedRoots = _roots,
        }.Send())!;

        Assert.That(exception.StatusCode, Is.EqualTo(307));
        Assert.That(exception.Message, Does.Contain("it would leave TLS"));
        Assert.That(plain.Requests, Is.Empty);
    }

    [Test]
    public void RedirectToAnotherServer_DropsTheHeadersMeantForTheFirst()
    {
        using TestServer other = Server();
        other.Then("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        using TestServer first = Server();
        first.Then($"HTTP/1.1 302 Found\r\nLocation: /same\r\nContent-Length: 0\r\n\r\n");
        first.Then($"HTTP/1.1 302 Found\r\nLocation: {other.Url("/other")}\r\nContent-Length: 0\r\n\r\n");

        new HttpRequest(first.Url("/"))
        {
            Headers = { ["Authorization"] = "Bearer secret", ["Cookie"] = "session=1", ["Host"] = "virtual.test", ["X-Trace"] = "kept" },
            Timeout = Timeout,
            TrustedRoots = _roots,
        }.Send();

        TestRequest[] firstRequests = first.Requests.ToArray();
        Assert.That(firstRequests.Select(request => request.Headers["Authorization"]), Is.All.EqualTo("Bearer secret"));
        Assert.That(firstRequests.Select(request => request.Headers["Host"]), Is.All.EqualTo("virtual.test"));

        TestRequest redirected = other.Requests.Single();
        Assert.That(redirected.Headers.ContainsKey("Authorization"), Is.False);
        Assert.That(redirected.Headers.ContainsKey("Cookie"), Is.False);
        Assert.That(redirected.Headers["Host"], Is.EqualTo($"127.0.0.1:{other.Port}"));
        Assert.That(redirected.Headers["X-Trace"], Is.EqualTo("kept"));
    }

    [Test]
    public void UntrustedRoot_FailsTheHandshake()
    {
        using TestServer server = Server();
        server.Then(connection => connection.ReadRequest());

        HttpException exception = Assert.Throws<HttpException>(() =>
            new HttpRequest(server.Url("/")) { Timeout = Timeout, TrustedRoots = TrustedRoots.FromCertificates([TestPki.Root("Other").RawData]) }.Send())!;

        Assert.That(exception.Message, Does.StartWith("The certificate of 127.0.0.1 is not trusted: the chain goes up to CN=Test Root"));
        Assert.That(exception.StatusCode, Is.Zero);
        Assert.That(server.Requests, Is.Empty);
    }

    [Test]
    public void MozillaRoots_DoNotTrustATestRoot()
    {
        using TestServer server = Server();
        server.Then(connection => connection.ReadRequest());

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send())!;

        Assert.That(exception.Message, Does.Contain("is not trusted"));
    }

    [Test]
    public void OtherHost_FailsTheHandshake()
    {
        using TestServer server = Server(names: ["elsewhere.test"]);
        server.Then(connection => connection.ReadRequest());

        HttpException exception = Assert.Throws<HttpException>(() => Request(server.Url("/")).Send())!;

        Assert.That(exception.Message, Is.EqualTo("The certificate of 127.0.0.1 is not trusted: the certificate is for elsewhere.test, not 127.0.0.1."));
    }

    [Test]
    public void Validation_CanTrustASelfSignedServer()
    {
        X509Certificate2 selfSigned = TestPki.Server(null, ["127.0.0.1"]);
        using TestServer server = new(SslStreamCertificateContext.Create(selfSigned, null, offline: true));
        server.Then("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npin!");
        ServerCertificate? seen = null;

        HttpResponse response = new HttpRequest(server.Url("/"))
        {
            Timeout = Timeout,
            ServerCertificateValidation = certificate =>
            {
                seen = certificate;
                return certificate.Fingerprint == Convert.ToHexString(SHA256.HashData(selfSigned.RawData));
            },
        }.Send();

        Assert.That(response.GetString(), Is.EqualTo("pin!"));
        Assert.That(seen!.Error, Is.EqualTo("the certificate is self-signed"));
        Assert.That(seen.Host, Is.EqualTo("127.0.0.1"));
        Assert.That(seen.Subject, Is.EqualTo("CN=127.0.0.1"));
        Assert.That(seen.Chain.Single(), Is.EqualTo(selfSigned.RawData));
        Assert.That(seen.NotAfter, Is.EqualTo(selfSigned.NotAfter.ToUniversalTime()).Within(TimeSpan.FromSeconds(1)));
    }

    [Test]
    public void Validation_CanRefuseATrustedServer()
    {
        using TestServer server = Server();
        server.Then(connection => connection.ReadRequest());

        HttpException exception = Assert.Throws<HttpException>(() =>
            new HttpRequest(server.Url("/")) { Timeout = Timeout, TrustedRoots = _roots, ServerCertificateValidation = _ => false }.Send())!;

        Assert.That(exception.Message, Does.EndWith("is not trusted: ServerCertificateValidation refused it."));
    }

    [Test]
    public void Validation_ThatThrows_FailsTheRequestWithItsException()
    {
        using TestServer server = Server();
        server.Then(connection => connection.ReadRequest());
        InvalidOperationException thrown = new("no way");

        HttpException exception = Assert.Throws<HttpException>(() =>
            new HttpRequest(server.Url("/")) { Timeout = Timeout, TrustedRoots = _roots, ServerCertificateValidation = _ => throw thrown }.Send())!;

        Assert.That(exception.InnerException, Is.SameAs(thrown));
        Assert.That(exception.Message, Does.Contain("no way"));
    }

    [Test]
    public void SilentServer_TimesOutDuringTheHandshake()
    {
        using TestServer plain = new();
        plain.Then(connection => connection.Hang());

        // A plain server that never answers the ClientHello.
        string url = plain.Url("/").Replace("http://", "https://");
        HttpException exception = Assert.Throws<HttpException>(() =>
            new HttpRequest(url) { Timeout = 300, TrustedRoots = _roots }.Send())!;

        Assert.That(exception.Message, Does.Contain("did not finish the TLS handshake in 300 ms"));
    }

    [Test]
    public void PlainHttpServer_FailsTheHandshake()
    {
        using TestServer plain = new();
        plain.Then(connection => connection.Write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"));

        string url = plain.Url("/").Replace("http://", "https://");
        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(url) { Timeout = Timeout, TrustedRoots = _roots }.Send())!;

        Assert.That(exception.Message, Does.StartWith("The TLS handshake with 127.0.0.1:"));
    }

    private TestServer Server(SslProtocols protocols = SslProtocols.None, string[]? names = null)
    {
        X509Certificate2 certificate = TestPki.Server(_intermediate, names ?? ["localhost", "127.0.0.1"]);
        return new TestServer(SslStreamCertificateContext.Create(certificate, [_intermediate], offline: true), protocols);
    }

    private HttpRequest Request(string url) => new(url) { Timeout = Timeout, TrustedRoots = _roots };
}
