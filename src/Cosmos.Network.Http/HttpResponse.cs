// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Text;

namespace Cosmos.Network.Http;

/// <summary>
/// What a server answered: the status, the headers and the whole body.
/// <see cref="HttpRequest.Send"/> returns any status, error ones included;
/// <see cref="EnsureSuccessStatusCode"/> turns those into an exception.
/// </summary>
public sealed class HttpResponse
{
    /// <summary>The URL that answered: the one requested, or where its redirects led.</summary>
    public string Url { get; }

    /// <summary>The HTTP version the server answered with, such as <c>HTTP/1.1</c>.</summary>
    public string Version { get; }

    /// <summary>The status code, such as 200 or 404.</summary>
    public int StatusCode { get; }

    /// <summary>The text after the status code, such as <c>OK</c>; it may be empty.</summary>
    public string ReasonPhrase { get; }

    /// <summary>
    /// The headers, looked up case-insensitively. A header the server sent
    /// more than once holds its values joined by <c>", "</c>.
    /// </summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>
    /// The body, with any chunked transfer coding removed. It is empty for a
    /// HEAD request and for a 204 or 304.
    /// </summary>
    public byte[] Content { get; }

    /// <summary>Whether the status is a 2xx one.</summary>
    public bool IsSuccessStatusCode => StatusCode is >= 200 and <= 299;

    /// <summary>The Content-Type header, or null when the server sent none.</summary>
    public string? ContentType => GetHeader("Content-Type");

    internal HttpResponse(string url, string version, int statusCode, string reasonPhrase, Dictionary<string, string> headers, byte[] content)
    {
        Url = url;
        Version = version;
        StatusCode = statusCode;
        ReasonPhrase = reasonPhrase;
        Headers = headers;
        Content = content;
    }

    /// <summary>A header's value, or null when the server did not send it.</summary>
    public string? GetHeader(string name) => Headers.TryGetValue(name, out string? value) ? value : null;

    /// <summary>
    /// The body as text, decoded with the charset of the Content-Type header:
    /// UTF-8, US-ASCII, ISO-8859-1 or UTF-16. Any other charset, or none, is
    /// read as UTF-8. A byte order mark is not part of the text.
    /// </summary>
    public string GetString()
    {
        byte[] content = Content;
        if (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(content, 3, content.Length - 3);
        }

        return GetEncoding(GetCharset(ContentType)).GetString(content);
    }

    /// <summary>Throws unless the status is a 2xx one.</summary>
    /// <returns>This response, so the call can be chained.</returns>
    /// <exception cref="HttpException">The status is not a 2xx one; the exception carries it.</exception>
    public HttpResponse EnsureSuccessStatusCode()
    {
        if (!IsSuccessStatusCode)
        {
            string status = ReasonPhrase.Length == 0 ? $"{StatusCode}" : $"{StatusCode} {ReasonPhrase}";
            throw new HttpException($"{Url} answered {status}.", StatusCode);
        }

        return this;
    }

    private static string? GetCharset(string? contentType)
    {
        if (contentType is null)
        {
            return null;
        }

        foreach (string parameter in contentType.Split(';'))
        {
            string trimmed = parameter.Trim();
            if (trimmed.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed.Substring("charset=".Length).Trim('"', ' ');
            }
        }

        return null;
    }

    /// <summary>
    /// Only the encodings every .NET runtime has built in: a Cosmos kernel has
    /// no code page provider for <see cref="Encoding.GetEncoding(string)"/> to
    /// find the others in.
    /// </summary>
    private static Encoding GetEncoding(string? charset)
    {
        if (charset is null)
        {
            return Encoding.UTF8;
        }

        if (charset.Equals("us-ascii", StringComparison.OrdinalIgnoreCase) || charset.Equals("ascii", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.ASCII;
        }

        if (charset.Equals("iso-8859-1", StringComparison.OrdinalIgnoreCase) || charset.Equals("latin1", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.Latin1;
        }

        if (charset.Equals("utf-16", StringComparison.OrdinalIgnoreCase) || charset.Equals("utf-16le", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.Unicode;
        }

        if (charset.Equals("utf-16be", StringComparison.OrdinalIgnoreCase))
        {
            return Encoding.BigEndianUnicode;
        }

        return Encoding.UTF8;
    }
}
