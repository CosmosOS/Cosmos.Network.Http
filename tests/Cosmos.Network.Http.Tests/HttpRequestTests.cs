// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NUnit.Framework;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// Sends requests to a loopback server that answers with bytes the tests
/// write out, and checks what went over the wire both ways.
/// </summary>
[TestFixture]
public class HttpRequestTests
{
    // Short, so a client that waits for a close it should not need fails fast.
    private const int Timeout = 2000;

    [Test]
    public void Get_SendsAMinimalRequestAndReturnsTheBody()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello");

        HttpResponse response = new HttpRequest(server.Url("/page?x=1")) { Timeout = Timeout }.Send();

        Assert.That(response.StatusCode, Is.EqualTo(200));
        Assert.That(response.GetString(), Is.EqualTo("hello"));
        Assert.That(response.Url, Is.EqualTo(server.Url("/page?x=1")));

        TestRequest request = server.Requests.Single();
        Assert.That(request.Head, Does.StartWith("GET /page?x=1 HTTP/1.1\r\n"));
        Assert.That(request.Headers["Host"], Is.EqualTo($"127.0.0.1:{server.Port}"));
        Assert.That(request.Headers["Connection"], Is.EqualTo("close"));
        Assert.That(request.Headers["Accept-Encoding"], Is.EqualTo("identity"));
        Assert.That(request.Headers["User-Agent"], Is.EqualTo(HttpRequest.DefaultUserAgent));
        Assert.That(request.Headers.ContainsKey("Content-Length"), Is.False);
    }

    [Test]
    public void ContentLength_DoesNotWaitForTheServerToClose()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            connection.WaitForClientClose();
        });

        HttpResponse response = new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send();

        Assert.That(response.GetString(), Is.EqualTo("ok"));
    }

    [Test]
    public void Chunked_DoesNotWaitForTheServerToClose()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.WriteSlowly("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
            connection.WaitForClientClose();
        });

        HttpResponse response = new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send();

        Assert.That(response.GetString(), Is.EqualTo("abcde"));
    }

    [Test]
    public void NoLength_ReadsUntilTheServerCloses()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.WriteSlowly("HTTP/1.0 200 OK\r\n\r\n");
            connection.Write(new string('x', 100_000));
        });

        HttpResponse response = new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send();

        Assert.That(response.Content, Has.Length.EqualTo(100_000));
    }

    [Test]
    public void LargeBody_ArrivesWhole()
    {
        byte[] body = new byte[3 * 1024 * 1024];
        new Random(42).NextBytes(body);
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write($"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n");
            connection.Write(body);
        });

        HttpResponse response = new HttpRequest(server.Url("/big.bin")) { Timeout = Timeout }.Send();

        Assert.That(response.Content, Is.EqualTo(body));
    }

    [Test]
    public void Head_ReturnsNoBody()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");
            connection.WaitForClientClose();
        });

        HttpResponse response = new HttpRequest(server.Url("/")) { Method = "HEAD", Timeout = Timeout }.Send();

        Assert.That(response.Content, Is.Empty);
        Assert.That(response.GetHeader("Content-Length"), Is.EqualTo("1234"));
        Assert.That(server.Requests.Single().Method, Is.EqualTo("HEAD"));
    }

    [Test]
    public void Post_SendsTheBodyWithItsLength()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

        HttpResponse response = new HttpRequest(server.Url("/api"))
        {
            Method = "POST",
            Body = Encoding.UTF8.GetBytes("{\"a\":1}"),
            Headers = { ["Content-Type"] = "application/json" },
            Timeout = Timeout,
        }.Send();

        Assert.That(response.StatusCode, Is.EqualTo(201));
        TestRequest request = server.Requests.Single();
        Assert.That(request.Method, Is.EqualTo("POST"));
        Assert.That(request.Headers["Content-Length"], Is.EqualTo("7"));
        Assert.That(request.Headers["Content-Type"], Is.EqualTo("application/json"));
        Assert.That(Encoding.UTF8.GetString(request.Body), Is.EqualTo("{\"a\":1}"));
    }

    [Test]
    public void PostWithoutBody_SendsAZeroLength()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 204 No Content\r\n\r\n");

        new HttpRequest(server.Url("/")) { Method = "POST", Timeout = Timeout }.Send();

        Assert.That(server.Requests.Single().Headers["Content-Length"], Is.EqualTo("0"));
    }

    [Test]
    public void Headers_ReplaceTheDefaultsAndAddToThem()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        new HttpRequest(server.Url("/"))
        {
            Headers =
            {
                ["host"] = "virtual.example",
                ["User-Agent"] = "AuraOS/1.0",
                ["X-Extra"] = "yes",
            },
            Timeout = Timeout,
        }.Send();

        TestRequest request = server.Requests.Single();
        Assert.That(request.Headers["Host"], Is.EqualTo("virtual.example"));
        Assert.That(request.Headers["User-Agent"], Is.EqualTo("AuraOS/1.0"));
        Assert.That(request.Headers["X-Extra"], Is.EqualTo("yes"));
        Assert.That(request.Head.Split("\r\n").Count(line => line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
    }

    [TestCase("Connection")]
    [TestCase("content-length")]
    [TestCase("Transfer-Encoding")]
    public void Headers_TheRequestSetsItselfAreRefused(string name)
    {
        HttpRequest request = new("http://127.0.0.1:1/") { Headers = { [name] = "x" } };

        Assert.Throws<InvalidOperationException>(() => request.Send());
    }

    [Test]
    public void Headers_ThatBreakTheLineAreRefused()
    {
        HttpRequest request = new("http://127.0.0.1:1/") { Headers = { ["X-Evil"] = "a\r\nInjected: yes" } };

        Assert.Throws<InvalidOperationException>(() => request.Send());
    }

    [Test]
    public void ErrorStatus_IsReturned_AndEnsureSuccessThrows()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found");

        HttpResponse response = new HttpRequest(server.Url("/missing")) { Timeout = Timeout }.Send();

        Assert.That(response.StatusCode, Is.EqualTo(404));
        Assert.That(response.GetString(), Is.EqualTo("not found"));
        HttpException exception = Assert.Throws<HttpException>(() => response.EnsureSuccessStatusCode())!;
        Assert.That(exception.StatusCode, Is.EqualTo(404));
        Assert.That(exception.Message, Does.Contain("404 Not Found"));
    }

    [Test]
    public void Redirects_AreFollowed()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
            .Then($"HTTP/1.1 302 Found\r\nLocation: {server.Url("/last")}\r\nContent-Length: 0\r\n\r\n")
            .Then("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone");
        List<string> log = [];

        HttpResponse response = new HttpRequest(server.Url("/first")) { Timeout = Timeout, Log = log.Add }.Send();

        Assert.That(response.GetString(), Is.EqualTo("done"));
        Assert.That(response.Url, Is.EqualTo(server.Url("/last")));
        Assert.That(server.Requests.Select(request => request.Target), Is.EqualTo(new[] { "/first", "/next", "/last" }));
        Assert.That(log, Has.Count.EqualTo(5));
    }

    [Test]
    public void SeeOther_TurnsAPostIntoAGet()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 303 See Other\r\nLocation: /result\r\nContent-Length: 0\r\n\r\n")
            .Then("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        new HttpRequest(server.Url("/form")) { Method = "POST", Body = [1, 2, 3], Timeout = Timeout }.Send();

        TestRequest second = server.Requests.Last();
        Assert.That(second.Method, Is.EqualTo("GET"));
        Assert.That(second.Body, Is.Empty);
        Assert.That(second.Headers.ContainsKey("Content-Length"), Is.False);
    }

    [Test]
    public void TemporaryRedirect_KeepsThePost()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n")
            .Then("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        new HttpRequest(server.Url("/form")) { Method = "POST", Body = [1, 2, 3], Timeout = Timeout }.Send();

        TestRequest second = server.Requests.Last();
        Assert.That(second.Method, Is.EqualTo("POST"));
        Assert.That(second.Body, Is.EqualTo(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public void Redirects_StopAtTheLimit()
    {
        using TestServer server = new();
        for (int i = 0; i < 3; i++)
        {
            server.Then("HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n");
        }

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { MaxRedirects = 2, Timeout = Timeout }.Send())!;
        Assert.That(exception.StatusCode, Is.EqualTo(302));
    }

    [Test]
    public void Redirects_AreReturnedWithoutLimit()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n");

        HttpResponse response = new HttpRequest(server.Url("/")) { MaxRedirects = 0, Timeout = Timeout }.Send();

        Assert.That(response.StatusCode, Is.EqualTo(301));
        Assert.That(response.GetHeader("Location"), Is.EqualTo("/next"));
    }

    [Test]
    public void RedirectToAnotherScheme_Throws()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 301 Moved Permanently\r\nLocation: ftp://files.example/\r\nContent-Length: 0\r\n\r\n");

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send())!;
        Assert.That(exception.StatusCode, Is.EqualTo(301));
        Assert.That(exception.Message, Does.Contain("ftp://files.example/"));
    }

    [Test]
    public void SilentServer_TimesOut()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Hang();
        });

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { Timeout = 300 }.Send())!;
        Assert.That(exception.Message, Does.Contain("sent nothing"));
    }

    [Test]
    public void TruncatedBody_Throws()
    {
        using TestServer server = new();
        server.Then("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send())!;
        Assert.That(exception.Message, Does.Contain("3 of 10"));
    }

    [Test]
    public void ClosedWithoutAnswer_Throws()
    {
        using TestServer server = new();
        server.Then(connection => connection.ReadRequest());

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest(server.Url("/")) { Timeout = Timeout }.Send())!;
        Assert.That(exception.Message, Does.Contain("without answering"));
    }

    [Test]
    public void RefusedConnection_Throws()
    {
        // A port nothing listens on: bound, then released.
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest($"http://127.0.0.1:{port}/") { Timeout = Timeout }.Send())!;
        Assert.That(exception.Message, Does.StartWith($"Could not connect to 127.0.0.1:{port}"));
    }

    [Test]
    public void UnknownHost_Throws()
    {
        HttpException exception = Assert.Throws<HttpException>(() => new HttpRequest("http://no-such-host.invalid/") { Timeout = Timeout }.Send())!;
        Assert.That(exception.Message, Does.StartWith("Could not resolve no-such-host.invalid"));
    }

    [Test]
    public void GetString_UsesTheCharsetAndSkipsTheByteOrderMark()
    {
        using TestServer server = new();
        server.Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=\"ISO-8859-1\"\r\nContent-Length: 1\r\n\r\n");
            connection.Write([0xE9]);
        }).Then(connection =>
        {
            connection.ReadRequest();
            connection.Write("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
            connection.Write([0xEF, 0xBB, 0xBF, (byte)'{']);
        });

        Assert.That(new HttpRequest(server.Url("/latin1")) { Timeout = Timeout }.Send().GetString(), Is.EqualTo("é"));
        Assert.That(new HttpRequest(server.Url("/bom")) { Timeout = Timeout }.Send().GetString(), Is.EqualTo("{"));
    }

    [TestCase("GET POST")]
    [TestCase("G\r\nET")]
    [TestCase("")]
    public void Method_MustBeAToken(string method)
    {
        Assert.Throws<ArgumentException>(() => _ = new HttpRequest("http://host/") { Method = method });
    }

    [Test]
    public void Settings_AreValidated()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new HttpRequest("http://host/") { Timeout = 0 });
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new HttpRequest("http://host/") { MaxRedirects = -1 });
        Assert.Throws<ArgumentException>(() => _ = new HttpRequest(" "));
        Assert.Throws<NotSupportedException>(() => _ = new HttpRequest("ftp://host/"));
    }
}
