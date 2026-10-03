// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Cosmos.Network.Http;

/// <summary>
/// Takes a response apart as its bytes arrive, and tells when it has arrived
/// whole (RFC 9112, section 6.3), so the connection need not be read to its
/// end: a response with a Content-Length or a chunked body is complete
/// before the server closes. One without either ends where the connection
/// does.
/// </summary>
internal sealed class ResponseReader
{
    /// <summary>The longest response head taken, in bytes.</summary>
    internal const int MaxHeadLength = 64 * 1024;

    /// <summary>The largest Content-Length the receive buffer is sized for up front, in bytes.</summary>
    private const int MaxPreallocatedLength = 64 * 1024 * 1024;

    private enum Framing
    {
        /// <summary>No body: a response to HEAD, a 1xx, a 204 or a 304.</summary>
        None,

        /// <summary>As many bytes as Content-Length says.</summary>
        Length,

        /// <summary>The chunked transfer coding.</summary>
        Chunked,

        /// <summary>Everything up to the end of the connection.</summary>
        UntilClose,
    }

    private readonly MemoryStream _received = new();
    private readonly bool _isHead;

    private Head? _head;
    private Framing _framing;
    private long _contentLength;

    /// <summary>Where the head being looked for starts: past any 1xx interim response.</summary>
    private int _headStart;

    /// <summary>Where the search for the end of that head resumes.</summary>
    private int _scanFrom;

    private int _bodyStart;

    /// <summary>Where the search for the end of a chunked body resumes.</summary>
    private int _chunkScan;

    /// <param name="isHead">Whether the request was a HEAD one, whose response has no body whatever its headers say.</param>
    public ResponseReader(bool isHead)
    {
        _isHead = isHead;
    }

    /// <summary>Whether the whole response has arrived.</summary>
    public bool IsComplete { get; private set; }

    /// <summary>Takes the next bytes of the response.</summary>
    /// <exception cref="HttpException">The bytes are not an HTTP response.</exception>
    public void Append(byte[] buffer, int count)
    {
        _received.Write(buffer, 0, count);

        if (_head is null && !TryReadHead())
        {
            return;
        }

        IsComplete = _framing switch
        {
            Framing.None => true,
            Framing.Length => _received.Length - _bodyStart >= _contentLength,
            Framing.Chunked => ChunkedBody.FindEnd(_received.GetBuffer(), (int)_received.Length, ref _chunkScan),
            _ => false,
        };
    }

    /// <summary>
    /// The response, once it is complete or the server has closed the
    /// connection, which completes a response that runs until it does.
    /// </summary>
    /// <param name="url">The URL that answered.</param>
    /// <exception cref="HttpException">The connection closed before the response was whole.</exception>
    public HttpResponse ToResponse(string url)
    {
        if (_head is null)
        {
            throw new HttpException(_received.Length == _headStart
                ? "The server closed the connection without answering."
                : "The server closed the connection in the middle of the response head.");
        }

        byte[] data = _received.GetBuffer();
        int received = (int)_received.Length - _bodyStart;
        byte[] content;
        switch (_framing)
        {
            case Framing.None:
                content = [];
                break;

            case Framing.Length:
                if (received < _contentLength)
                {
                    throw new HttpException($"The server closed the connection after {received} of {_contentLength} bytes.", _head.StatusCode);
                }

                content = Slice(data, _bodyStart, (int)_contentLength);
                break;

            case Framing.Chunked:
                content = ChunkedBody.Decode(data, _bodyStart, (int)_received.Length);
                break;

            default:
                content = Slice(data, _bodyStart, received);
                break;
        }

        return new HttpResponse(url, _head.Version, _head.StatusCode, _head.ReasonPhrase, _head.Headers, content);
    }

    /// <summary>Looks for the end of the head, and takes the head apart once it arrived.</summary>
    /// <returns>Whether the head of the final response arrived.</returns>
    private bool TryReadHead()
    {
        byte[] data = _received.GetBuffer();
        int length = (int)_received.Length;

        while (true)
        {
            int end = IndexOfHeadEnd(data, _scanFrom, length);
            if (end < 0)
            {
                if (length - _headStart > MaxHeadLength)
                {
                    throw new HttpException($"The response head is longer than {MaxHeadLength} bytes.");
                }

                // The blank line may straddle what arrives next.
                _scanFrom = Math.Max(_headStart, length - 3);
                return false;
            }

            Head head = ParseHead(data, _headStart, end - _headStart);
            if (head.StatusCode is >= 100 and <= 199 && head.StatusCode != 101)
            {
                // An interim response, such as 100 Continue: the final one follows.
                _headStart = _scanFrom = end;
                continue;
            }

            _head = head;
            _bodyStart = _chunkScan = end;
            ChooseFraming(head);
            return true;
        }
    }

    private void ChooseFraming(Head head)
    {
        if (_isHead || head.StatusCode is 204 or 304 or (>= 100 and <= 199))
        {
            _framing = Framing.None;
            return;
        }

        // Transfer-Encoding wins over Content-Length. A coding other than
        // chunked last leaves nothing to tell the end of the body by but the
        // end of the connection.
        if (head.Headers.TryGetValue("Transfer-Encoding", out string? transferEncoding))
        {
            _framing = transferEncoding.Trim().EndsWith("chunked", StringComparison.OrdinalIgnoreCase) ? Framing.Chunked : Framing.UntilClose;
            return;
        }

        if (head.Headers.TryGetValue("Content-Length", out string? contentLength))
        {
            _framing = Framing.Length;
            _contentLength = ParseContentLength(contentLength);
            if (_contentLength <= MaxPreallocatedLength)
            {
                _received.Capacity = Math.Max(_received.Capacity, _bodyStart + (int)_contentLength);
            }

            return;
        }

        _framing = Framing.UntilClose;
    }

    /// <summary>
    /// A Content-Length, which a server that sent it more than once joined
    /// with commas: taken if every copy agrees (RFC 9110, section 8.6).
    /// </summary>
    private static long ParseContentLength(string value)
    {
        long length = -1;
        foreach (string part in value.Split(','))
        {
            if (!long.TryParse(part.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed)
                || parsed > int.MaxValue
                || (length >= 0 && parsed != length))
            {
                throw new HttpException($"The response has an invalid Content-Length: {value}.");
            }

            length = parsed;
        }

        return length;
    }

    /// <summary>Takes apart a status line and the header lines after it (RFC 9112, sections 4 and 5).</summary>
    private static Head ParseHead(byte[] data, int start, int length)
    {
        // Headers are ASCII but for the odd value, which UTF-8 reads as well as anything.
        string[] lines = Encoding.UTF8.GetString(data, start, length).Split("\r\n");
        string statusLine = lines[0];

        // HTTP-version SP 3DIGIT [SP reason-phrase]
        int space = statusLine.IndexOf(' ');
        int statusCode = 0;
        if (!statusLine.StartsWith("HTTP/", StringComparison.Ordinal)
            || space < 0
            || statusLine.Length < space + 4
            || (statusLine.Length > space + 4 && statusLine[space + 4] != ' ')
            || !int.TryParse(statusLine.Substring(space + 1, 3), NumberStyles.None, CultureInfo.InvariantCulture, out statusCode))
        {
            string shown = statusLine.Length > 64 ? statusLine.Substring(0, 64) + "..." : statusLine;
            throw new HttpException($"The server answered with something that is not HTTP: {shown}");
        }

        string version = statusLine.Substring(0, space);
        string reasonPhrase = statusLine.Length > space + 5 ? statusLine.Substring(space + 5) : string.Empty;

        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i];
            int colon = line.IndexOf(':');

            // Lines with no name, and the obsolete continuations that start with whitespace, hold nothing to keep.
            if (colon <= 0 || line[0] is ' ' or '\t')
            {
                continue;
            }

            string name = line.Substring(0, colon).Trim();
            string value = line.Substring(colon + 1).Trim();
            headers[name] = headers.TryGetValue(name, out string? previous) ? previous + ", " + value : value;
        }

        return new Head(version, statusCode, reasonPhrase, headers);
    }

    /// <summary>The index just past the blank line that ends a head, or -1.</summary>
    private static int IndexOfHeadEnd(byte[] data, int start, int length)
    {
        for (int i = start; i + 3 < length; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
            {
                return i + 4;
            }
        }

        return -1;
    }

    private static byte[] Slice(byte[] data, int start, int length)
    {
        byte[] slice = new byte[length];
        Buffer.BlockCopy(data, start, slice, 0, length);
        return slice;
    }

    private sealed class Head(string version, int statusCode, string reasonPhrase, Dictionary<string, string> headers)
    {
        public string Version { get; } = version;

        public int StatusCode { get; } = statusCode;

        public string ReasonPhrase { get; } = reasonPhrase;

        public Dictionary<string, string> Headers { get; } = headers;
    }
}
