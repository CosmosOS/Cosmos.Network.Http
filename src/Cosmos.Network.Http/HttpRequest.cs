// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Generic;
using System.Text;

namespace Cosmos.Network.Http;

/// <summary>
/// An HTTP/1.1 request to an http:// or https:// URL. <see cref="Send"/> runs
/// it on the calling thread, follows redirects, and returns the response whole.
/// </summary>
/// <remarks>
/// <para>
/// Each request opens a connection of its own and asks the server to close
/// it once it has answered. Responses are asked for without content coding
/// (<c>Accept-Encoding: identity</c>): the body comes as the server stores it.
/// </para>
/// <para>
/// An https:// request runs TLS 1.3 or 1.2 (BouncyCastle's), and goes on only
/// with a server whose certificate leads to one of Mozilla's roots and names
/// the host, unless <see cref="ServerCertificateValidation"/> decides
/// otherwise. There is no revocation check.
/// </para>
/// </remarks>
public sealed class HttpRequest
{
    /// <summary>How long the server may stay silent by default, in milliseconds.</summary>
    public const int DefaultTimeout = 15_000;

    /// <summary>How many redirects are followed by default.</summary>
    public const int DefaultMaxRedirects = 5;

    /// <summary>The User-Agent sent unless <see cref="Headers"/> names one.</summary>
    public const string DefaultUserAgent = "Cosmos.Network.Http/2.1";

    /// <summary>
    /// Headers the request sets itself: Connection tells where a response
    /// without a length ends, Content-Length frames the body.
    /// </summary>
    private static readonly string[] s_reservedHeaders = ["Connection", "Content-Length", "Transfer-Encoding"];

    /// <summary>
    /// Headers meant for the URL's own server, left out once a redirect
    /// leads to another one: credentials, and a Host set by hand.
    /// </summary>
    private static readonly string[] s_originHeaders = ["Authorization", "Proxy-Authorization", "Cookie", "Host"];

    private readonly HttpUrl _url;
    private readonly string _method = "GET";
    private readonly int _timeout = DefaultTimeout;
    private readonly int _maxRedirects = DefaultMaxRedirects;

    /// <summary>Creates a request; <see cref="Send"/> sends it.</summary>
    /// <param name="url">An http:// or https:// URL. One without a scheme is taken as an http:// one, as wget takes it.</param>
    /// <exception cref="ArgumentException"><paramref name="url"/> is empty.</exception>
    /// <exception cref="NotSupportedException"><paramref name="url"/> is neither an http:// nor an https:// URL, or it carries credentials.</exception>
    /// <exception cref="FormatException"><paramref name="url"/> names no host, or a port that is not a TCP port.</exception>
    public HttpRequest(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        _url = HttpUrl.Parse(url);
    }

    /// <summary>The URL the request goes to, written out in full.</summary>
    public string Url => _url.ToString();

    /// <summary>The method, <c>GET</c> unless set: <c>HEAD</c>, <c>POST</c>, <c>PUT</c>, <c>DELETE</c> and so on.</summary>
    public string Method
    {
        get => _method;
        init
        {
            ArgumentException.ThrowIfNullOrEmpty(value);
            if (!IsToken(value))
            {
                throw new ArgumentException($"'{value}' is not an HTTP method.", nameof(value));
            }

            _method = value;
        }
    }

    /// <summary>The body sent after the head, if any; a POST, PUT or PATCH without one sends an empty body.</summary>
    public byte[]? Body { get; init; }

    /// <summary>
    /// Headers sent with the request, looked up case-insensitively. They
    /// replace the ones the request sends by default: Host, User-Agent,
    /// Accept and Accept-Encoding. Connection, Content-Length and
    /// Transfer-Encoding are the request's own, and cannot be set.
    /// </summary>
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How long the server may stay silent while it answers before the request fails, in milliseconds.</summary>
    public int Timeout
    {
        get => _timeout;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
            _timeout = value;
        }
    }

    /// <summary>
    /// How many redirects (301, 302, 303, 307, 308) are followed. With 0,
    /// <see cref="Send"/> returns the redirect itself.
    /// </summary>
    public int MaxRedirects
    {
        get => _maxRedirects;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _maxRedirects = value;
        }
    }

    /// <summary>Receives a line for every response and redirect, when set.</summary>
    public Action<string>? Log { get; init; }

    /// <summary>
    /// Decides whether to go on with an https:// server, given the
    /// certificates it presented and what the built-in check made of them
    /// (<see cref="ServerCertificate.Error"/>). When not set, the request goes
    /// on exactly when the built-in check trusts the server. It runs during
    /// the TLS handshake, on the thread that sends the request.
    /// </summary>
    /// <example>
    /// Trusting one self-signed server besides the ones Mozilla's roots vouch for:
    /// <code>
    /// ServerCertificateValidation = certificate => certificate.Error is null
    ///     || certificate.Fingerprint == "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
    /// </code>
    /// </example>
    public Func<ServerCertificate, bool>? ServerCertificateValidation { get; init; }

    /// <summary>The roots an https:// server's certificate must lead to: Mozilla's unless a test sets others.</summary>
    internal TrustedRoots? TrustedRoots { get; init; }

    /// <summary>
    /// Sends the request on the calling thread, follows redirects, and
    /// returns the response once it has arrived whole. Any status is
    /// returned, error ones included.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A 303, and a 301 or 302 to a POST, turn the request into a GET without
    /// a body, as browsers do. The other redirects send it again as it was.
    /// </para>
    /// <para>
    /// A redirect from https:// to http:// is not followed: it would send the
    /// request, and take the response, unencrypted. Once a redirect leads to
    /// another server (another scheme, host or port), the Authorization,
    /// Proxy-Authorization, Cookie and Host set in <see cref="Headers"/> are
    /// no longer sent: they were meant for the first one.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException"><see cref="Headers"/> sets a header the request sets itself, or holds a name or a value that cannot be sent.</exception>
    /// <exception cref="HttpException">The host could not be resolved or reached, the TLS handshake failed or the server's certificate is not trusted, the server went silent for longer than <see cref="Timeout"/>, the response did not come whole or is not HTTP, or the redirects went on for longer than <see cref="MaxRedirects"/> or to a URL that cannot be followed. When <see cref="ServerCertificateValidation"/> throws, its exception is the <see cref="Exception.InnerException"/>.</exception>
    public HttpResponse Send()
    {
        CheckHeaders();

        HttpUrl url = _url;
        string method = _method;
        byte[]? body = Body;
        bool sameOrigin = true;

        for (int redirects = 0; ; redirects++)
        {
            HttpResponse response = HttpConnection.Exchange(url, BuildRequest(url, method, body, sameOrigin), method == "HEAD", _timeout,
                TrustedRoots, ServerCertificateValidation);
            Log?.Invoke($"{method} {url} {response.StatusCode} {response.ReasonPhrase} ({response.Content.Length} bytes)");

            string? location = response.GetHeader("Location");
            if (!IsRedirect(response.StatusCode) || location is null || _maxRedirects == 0)
            {
                return response;
            }

            if (redirects == _maxRedirects)
            {
                throw new HttpException($"{_url} redirected more than {_maxRedirects} times.", response.StatusCode);
            }

            HttpUrl next;
            try
            {
                next = url.Resolve(location);
            }
            catch (Exception exception)
            {
                // NotSupportedException (neither http:// nor https://) or FormatException.
                throw new HttpException($"{url} redirected to a URL that cannot be followed: {exception.Message}", response.StatusCode);
            }

            if (url.IsSecure && !next.IsSecure)
            {
                throw new HttpException($"{url} redirected to {next}, which is not followed: it would leave TLS.", response.StatusCode);
            }

            sameOrigin &= next.IsSecure == url.IsSecure && next.Port == url.Port
                && next.Host.Equals(url.Host, StringComparison.OrdinalIgnoreCase);

            if ((response.StatusCode == 303 && method != "HEAD") || (response.StatusCode is 301 or 302 && method == "POST"))
            {
                method = "GET";
                body = null;
            }

            Log?.Invoke($"Redirected to {next}");
            url = next;
        }
    }

    private void CheckHeaders()
    {
        foreach (KeyValuePair<string, string> header in Headers)
        {
            foreach (string reserved in s_reservedHeaders)
            {
                if (header.Key.Equals(reserved, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"The {reserved} header is set by the request itself.");
                }
            }

            if (!IsToken(header.Key))
            {
                throw new InvalidOperationException($"'{header.Key}' is not a header name.");
            }

            if (header.Value is null || header.Value.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
            {
                throw new InvalidOperationException($"The value of the {header.Key} header cannot be sent: it is null or breaks the line.");
            }
        }
    }

    /// <param name="url">Where the request goes.</param>
    /// <param name="method">Its method.</param>
    /// <param name="body">Its body, if any.</param>
    /// <param name="sameOrigin">Whether it still goes to the server of the request's own URL, which <see cref="s_originHeaders"/> are meant for.</param>
    private byte[] BuildRequest(HttpUrl url, string method, byte[]? body, bool sameOrigin)
    {
        StringBuilder head = new();
        head.Append(method).Append(' ').Append(url.Target).Append(" HTTP/1.1\r\n");
        if (sameOrigin)
        {
            AppendHeader(head, "Host", url.Authority);
        }
        else
        {
            head.Append("Host: ").Append(url.Authority).Append("\r\n");
        }

        AppendHeader(head, "User-Agent", DefaultUserAgent);
        AppendHeader(head, "Accept", "*/*");
        // Nothing gzip or deflate would have to undo: a Cosmos kernel has no System.IO.Compression.
        AppendHeader(head, "Accept-Encoding", "identity");
        head.Append("Connection: close\r\n");

        if (body is not null || method is "POST" or "PUT" or "PATCH")
        {
            head.Append("Content-Length: ").Append(body is null ? 0 : body.Length).Append("\r\n");
        }

        foreach (KeyValuePair<string, string> header in Headers)
        {
            if (!IsDefaultHeader(header.Key) && (sameOrigin || !IsOriginHeader(header.Key)))
            {
                head.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
            }
        }

        head.Append("\r\n");

        byte[] headBytes = Encoding.UTF8.GetBytes(head.ToString());
        if (body is null || body.Length == 0)
        {
            return headBytes;
        }

        byte[] request = new byte[headBytes.Length + body.Length];
        Buffer.BlockCopy(headBytes, 0, request, 0, headBytes.Length);
        Buffer.BlockCopy(body, 0, request, headBytes.Length, body.Length);
        return request;
    }

    /// <summary>Appends a header the request sends by default, with the value <see cref="Headers"/> gives it if any.</summary>
    private void AppendHeader(StringBuilder head, string name, string defaultValue)
    {
        string value = Headers.TryGetValue(name, out string? set) ? set : defaultValue;
        head.Append(name).Append(": ").Append(value).Append("\r\n");
    }

    private static bool IsDefaultHeader(string name) =>
        name.Equals("Host", StringComparison.OrdinalIgnoreCase)
        || name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Accept", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase);

    private static bool IsOriginHeader(string name)
    {
        foreach (string origin in s_originHeaders)
        {
            if (name.Equals(origin, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsRedirect(int statusCode) => statusCode is 301 or 302 or 303 or 307 or 308;

    /// <summary>Whether <paramref name="value"/> is a token (RFC 9110, section 5.6.2), as methods and header names are.</summary>
    private static bool IsToken(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (!char.IsAsciiLetterOrDigit(c) && "!#$%&'*+-.^_`|~".IndexOf(c) < 0)
            {
                return false;
            }
        }

        return true;
    }
}
