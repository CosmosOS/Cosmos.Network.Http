// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using NUnit.Framework;

namespace Cosmos.Network.Http.Tests;

[TestFixture]
public class HttpUrlTests
{
    [TestCase("http://httpforever.com/", "httpforever.com", 80, "/")]
    [TestCase("http://httpforever.com", "httpforever.com", 80, "/")]
    [TestCase("HTTP://Example.com/a/b.html", "Example.com", 80, "/a/b.html")]
    [TestCase("httpforever.com/page", "httpforever.com", 80, "/page")]
    [TestCase("http://10.0.2.2:8080/x?y=1", "10.0.2.2", 8080, "/x?y=1")]
    [TestCase("http://host?q=1", "host", 80, "/?q=1")]
    [TestCase("http://host/a#section", "host", 80, "/a")]
    [TestCase("http://host:/a", "host", 80, "/a")]
    [TestCase("  http://host/a  ", "host", 80, "/a")]
    [TestCase("http://[::1]:8000/", "::1", 8000, "/")]
    [TestCase("host/search?u=http://other/", "host", 80, "/search?u=http://other/")]
    [TestCase("https://example.com/", "example.com", 443, "/")]
    [TestCase("HTTPS://example.com:8443/a?b", "example.com", 8443, "/a?b")]
    [TestCase("https://host:/a", "host", 443, "/a")]
    public void Parse_TakesTheUrlApart(string url, string host, int port, string target)
    {
        HttpUrl parsed = HttpUrl.Parse(url);

        Assert.Multiple(() =>
        {
            Assert.That(parsed.Host, Is.EqualTo(host));
            Assert.That(parsed.Port, Is.EqualTo(port));
            Assert.That(parsed.Target, Is.EqualTo(target));
        });
    }

    [TestCase("http://host/", false)]
    [TestCase("host/", false)]
    [TestCase("https://host/", true)]
    [TestCase("HtTpS://host/", true)]
    public void Parse_TellsWhetherTheUrlIsSecure(string url, bool isSecure)
    {
        Assert.That(HttpUrl.Parse(url).IsSecure, Is.EqualTo(isSecure));
    }

    [TestCase("http://host/", "host")]
    [TestCase("http://host:8080/", "host:8080")]
    [TestCase("http://[::1]:8080/", "[::1]:8080")]
    [TestCase("http://host:443/", "host:443")]
    [TestCase("https://host:443/", "host")]
    [TestCase("https://host:80/", "host:80")]
    [TestCase("https://[::1]/", "[::1]")]
    public void Authority_LeavesOutTheDefaultPort(string url, string authority)
    {
        Assert.That(HttpUrl.Parse(url).Authority, Is.EqualTo(authority));
    }

    [TestCase("https://Host/a", "https://Host/a")]
    [TestCase("https://host:443/a", "https://host/a")]
    [TestCase("https://host:8443", "https://host:8443/")]
    public void ToString_WritesTheUrlOutInFull(string url, string expected)
    {
        Assert.That(HttpUrl.Parse(url).ToString(), Is.EqualTo(expected));
    }

    [Test]
    public void Parse_PercentEncodesWhatARequestLineCannotCarry()
    {
        Assert.That(HttpUrl.Parse("http://host/a file/é?x=a b").Target, Is.EqualTo("/a%20file/%C3%A9?x=a%20b"));
        Assert.That(HttpUrl.Parse("http://host/a%20b").Target, Is.EqualTo("/a%20b"));
    }

    [TestCase("ftp://host/")]
    [TestCase("wss://host/")]
    [TestCase("http://user:pass@host/")]
    [TestCase("https://user@host/")]
    public void Parse_RefusesWhatItDoesNotSupport(string url)
    {
        Assert.Throws<NotSupportedException>(() => HttpUrl.Parse(url));
    }

    [TestCase("http://")]
    [TestCase("http:///path")]
    [TestCase("http://host:0/")]
    [TestCase("http://host:65536/")]
    [TestCase("http://host:http/")]
    [TestCase("http://[::1/")]
    [TestCase("http://[::1]x/")]
    public void Parse_RefusesMalformedUrls(string url)
    {
        Assert.Throws<FormatException>(() => HttpUrl.Parse(url));
    }

    [TestCase("http://other:81/x", "http://other:81/x")]
    [TestCase("//other/x", "http://other/x")]
    [TestCase("/x/y", "http://host:8080/x/y")]
    [TestCase("?page=2", "http://host:8080/dir/file?page=2")]
    [TestCase("other", "http://host:8080/dir/other")]
    [TestCase("sub/other?a=1", "http://host:8080/dir/sub/other?a=1")]
    [TestCase("#top", "http://host:8080/dir/file?q=1")]
    [TestCase("/a b", "http://host:8080/a%20b")]
    public void Resolve_FollowsEveryKindOfLocation(string location, string expected)
    {
        HttpUrl url = HttpUrl.Parse("http://host:8080/dir/file?q=1");

        Assert.That(url.Resolve(location).ToString(), Is.EqualTo(expected));
    }

    [TestCase("http://host/a", "https://other/b", "https://other/b")]
    [TestCase("https://host/a", "http://other/b", "http://other/b")]
    [TestCase("https://host/a", "//other/b", "https://other/b")]
    [TestCase("https://host:8443/a/b", "c", "https://host:8443/a/c")]
    [TestCase("https://host/a", "/c?d", "https://host/c?d")]
    public void Resolve_KeepsOrChangesTheScheme(string url, string location, string expected)
    {
        Assert.That(HttpUrl.Parse(url).Resolve(location).ToString(), Is.EqualTo(expected));
    }

    [Test]
    public void Resolve_RefusesOtherSchemes()
    {
        Assert.Throws<NotSupportedException>(() => HttpUrl.Parse("https://host/").Resolve("ftp://host/"));
    }
}
