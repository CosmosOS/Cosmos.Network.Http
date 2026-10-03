// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System.Text;
using NUnit.Framework;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// Feeds responses to the reader in every split a connection could deliver
/// them in, and checks it tells where they end.
/// </summary>
[TestFixture]
public class ResponseReaderTests
{
    private const string Url = "http://host/";

    [Test]
    public void ContentLength_CompletesWithoutTheConnectionClosing()
    {
        const string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";

        foreach (ResponseReader reader in FeedInEverySplit(response))
        {
            Assert.That(reader.IsComplete, Is.True);
            HttpResponse parsed = reader.ToResponse(Url);
            Assert.That(parsed.StatusCode, Is.EqualTo(200));
            Assert.That(parsed.ReasonPhrase, Is.EqualTo("OK"));
            Assert.That(parsed.Version, Is.EqualTo("HTTP/1.1"));
            Assert.That(parsed.ContentType, Is.EqualTo("text/plain"));
            Assert.That(Encoding.ASCII.GetString(parsed.Content), Is.EqualTo("hello"));
        }
    }

    [Test]
    public void ContentLength_IsNotCompleteBeforeTheLastByte()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhell");

        Assert.That(reader.IsComplete, Is.False);
        HttpException exception = Assert.Throws<HttpException>(() => reader.ToResponse(Url))!;
        Assert.That(exception.Message, Does.Contain("4 of 5"));
    }

    [Test]
    public void ContentLength_IgnoresBytesPastTheBody()
    {
        HttpResponse response = Feed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello").ToResponse(Url);

        Assert.That(Encoding.ASCII.GetString(response.Content), Is.EqualTo("he"));
    }

    [Test]
    public void Chunked_CompletesAtTheLastChunkAndTrailers()
    {
        const string response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "5;name=value\r\nhello\r\n"
            + "1\r\n,\r\n"
            + "6 \r\n world\r\n"
            + "0\r\nExpires: never\r\n\r\n";

        foreach (ResponseReader reader in FeedInEverySplit(response))
        {
            Assert.That(reader.IsComplete, Is.True);
            Assert.That(Encoding.ASCII.GetString(reader.ToResponse(Url).Content), Is.EqualTo("hello, world"));
        }
    }

    [Test]
    public void Chunked_IsNotCompleteBeforeTheBlankLineAfterTheLastChunk()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n");

        Assert.That(reader.IsComplete, Is.False);
    }

    [Test]
    public void Chunked_TruncatedBodyThrows()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\nabc");

        Assert.Throws<HttpException>(() => reader.ToResponse(Url));
    }

    [TestCase("zz")]
    [TestCase("")]
    [TestCase("5x")]
    public void Chunked_MalformedSizeThrows(string size)
    {
        Assert.Throws<HttpException>(() => Feed($"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nhello\r\n0\r\n\r\n"));
    }

    [Test]
    public void TransferEncoding_WinsOverContentLength()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n");

        Assert.That(reader.IsComplete, Is.True);
        Assert.That(Encoding.ASCII.GetString(reader.ToResponse(Url).Content), Is.EqualTo("ok"));
    }

    [Test]
    public void NoLength_RunsUntilTheConnectionCloses()
    {
        ResponseReader reader = Feed("HTTP/1.0 200 OK\r\n\r\neverything until the end");

        Assert.That(reader.IsComplete, Is.False);
        Assert.That(Encoding.ASCII.GetString(reader.ToResponse(Url).Content), Is.EqualTo("everything until the end"));
    }

    [TestCase(204)]
    [TestCase(304)]
    public void StatusesWithoutBody_CompleteAtTheHead(int status)
    {
        ResponseReader reader = Feed($"HTTP/1.1 {status} Whatever\r\nContent-Length: 10\r\n\r\n");

        Assert.That(reader.IsComplete, Is.True);
        Assert.That(reader.ToResponse(Url).Content, Is.Empty);
    }

    [Test]
    public void HeadRequest_CompletesAtTheHead()
    {
        ResponseReader reader = new(isHead: true);
        byte[] bytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");
        reader.Append(bytes, bytes.Length);

        Assert.That(reader.IsComplete, Is.True);
        HttpResponse response = reader.ToResponse(Url);
        Assert.That(response.Content, Is.Empty);
        Assert.That(response.GetHeader("content-length"), Is.EqualTo("1234"));
    }

    [Test]
    public void InterimResponses_AreSkipped()
    {
        const string response = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
            + "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";

        foreach (ResponseReader reader in FeedInEverySplit(response))
        {
            HttpResponse parsed = reader.ToResponse(Url);
            Assert.That(parsed.StatusCode, Is.EqualTo(201));
            Assert.That(parsed.GetHeader("Link"), Is.Null);
            Assert.That(Encoding.ASCII.GetString(parsed.Content), Is.EqualTo("ok"));
        }
    }

    [Test]
    public void Headers_AreCaseInsensitiveAndRepeatsAreJoined()
    {
        HttpResponse response = Feed("HTTP/1.1 200 OK\r\nX-Thing: a\r\nx-thing: b\r\nSpaced :  value  \r\nContent-Length: 0\r\n\r\n").ToResponse(Url);

        Assert.That(response.GetHeader("X-THING"), Is.EqualTo("a, b"));
        Assert.That(response.Headers["spaced"], Is.EqualTo("value"));
    }

    [Test]
    public void StatusLine_WithoutReasonPhrase()
    {
        HttpResponse response = Feed("HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n").ToResponse(Url);

        Assert.That(response.StatusCode, Is.EqualTo(404));
        Assert.That(response.ReasonPhrase, Is.Empty);
        Assert.That(response.IsSuccessStatusCode, Is.False);
    }

    [TestCase("SSH-2.0-OpenSSH_9.6\r\n\r\n")]
    [TestCase("HTTP/1.1 2000 OK\r\n\r\n")]
    [TestCase("HTTP/1.1 abc OK\r\n\r\n")]
    public void NotHttp_Throws(string response)
    {
        Assert.Throws<HttpException>(() => Feed(response));
    }

    [TestCase("abc")]
    [TestCase("5, 6")]
    [TestCase("-1")]
    public void InvalidContentLength_Throws(string length)
    {
        Assert.Throws<HttpException>(() => Feed($"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n"));
    }

    [Test]
    public void RepeatedContentLength_IsTakenWhenTheCopiesAgree()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok");

        Assert.That(reader.IsComplete, Is.True);
    }

    [Test]
    public void OversizedHead_Throws()
    {
        string response = "HTTP/1.1 200 OK\r\nX-Big: " + new string('a', ResponseReader.MaxHeadLength) + "\r\n";

        Assert.Throws<HttpException>(() => Feed(response));
    }

    [Test]
    public void NoAnswer_Throws()
    {
        HttpException exception = Assert.Throws<HttpException>(() => new ResponseReader(isHead: false).ToResponse(Url))!;
        Assert.That(exception.Message, Does.Contain("without answering"));
    }

    [Test]
    public void PartialHead_Throws()
    {
        ResponseReader reader = Feed("HTTP/1.1 200 OK\r\nContent-");

        HttpException exception = Assert.Throws<HttpException>(() => reader.ToResponse(Url))!;
        Assert.That(exception.Message, Does.Contain("middle of the response head"));
    }

    private static ResponseReader Feed(string response)
    {
        ResponseReader reader = new(isHead: false);
        byte[] bytes = Encoding.ASCII.GetBytes(response);
        reader.Append(bytes, bytes.Length);
        return reader;
    }

    /// <summary>The reader after the response arrived in two parts, for every place it can be split, and then a byte at a time.</summary>
    private static System.Collections.Generic.IEnumerable<ResponseReader> FeedInEverySplit(string response)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(response);
        for (int split = 0; split <= bytes.Length; split++)
        {
            ResponseReader reader = new(isHead: false);
            reader.Append(bytes[..split], split);
            reader.Append(bytes[split..], bytes.Length - split);
            yield return reader;
        }

        ResponseReader slow = new(isHead: false);
        foreach (byte b in bytes)
        {
            slow.Append([b], 1);
        }

        yield return slow;
    }
}
