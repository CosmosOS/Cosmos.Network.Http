// Cosmos: tests of what the port changed in the headers: .NET's read methods, the headers a caller may set, and a
// Content-Type read as .NET reads it.

using System;
using System.Collections.Generic;
using Cosmos.Network.Http.Headers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cosmos.Network.Http.Tests
{
    [TestClass]
    public class HeadersTests
    {
        [TestMethod]
        public void RequestHeaders_CallerHeaders_CanBeSet()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/");
            request.Headers.Add("Accept", "text/html");
            request.Headers.Add("User-Agent", "AuraOS/1");
            request.Headers.Add("Referer", "http://example.com/");
            request.Headers.Add("Range", "bytes=0-9");

            Assert.IsTrue(request.Headers.Contains("user-agent"));
            CollectionAssert.AreEqual(new[] { "text/html" }, new List<string>(request.Headers.GetValues("Accept")));

            Assert.IsTrue(request.Headers.Remove("Referer"));
            Assert.IsFalse(request.Headers.Remove("Referer"));
            Assert.IsFalse(request.Headers.TryGetValues("Referer", out _));

            Assert.ThrowsException<ArgumentException>(() => request.Headers.Add("Host", "example.org"));
            Assert.ThrowsException<ArgumentException>(() => request.Headers.Add("Transfer-Encoding", "chunked"));
            Assert.ThrowsException<ArgumentException>(() => request.Headers.Add("User-Agent", "bad\r\nInjected: yes"));
        }

        [TestMethod]
        public void ContentType_Absent_IsNull()
        {
            var content = new ByteArrayContent(new byte[1]);

            Assert.IsNull(content.Headers.ContentType);
        }

        [DataTestMethod]
        [DataRow("text/html; Charset=UTF-8", "text/html", "UTF-8")]
        [DataRow("multipart/form-data; boundary=x; charset=utf-8", "multipart/form-data", "utf-8")]
        [DataRow("application/json; charset=\"utf-8\";", "application/json", "utf-8")]
        [DataRow("image/png; name=a.png", "image/png", null)]
        public void ContentType_Parameters_AreRead(string header, string mediaType, string charSet)
        {
            MediaTypeHeaderValue value = MediaTypeHeaderValue.Parse(header);

            Assert.AreEqual(mediaType, value.MediaType);
            Assert.AreEqual(charSet, value.CharSet);
        }
    }
}
