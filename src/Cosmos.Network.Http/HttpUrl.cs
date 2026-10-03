// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Globalization;
using System.Text;

namespace Cosmos.Network.Http;

/// <summary>
/// An http:// or https:// URL taken apart into what a request needs: whether
/// to talk TLS, the host and port to connect to, and the target its request
/// line names. The fragment is dropped, as it never leaves the client.
/// </summary>
internal sealed class HttpUrl
{
    /// <summary>The port of an http:// URL that names none.</summary>
    public const int DefaultPort = 80;

    /// <summary>The port of an https:// URL that names none.</summary>
    public const int DefaultSecurePort = 443;

    private const string HexDigits = "0123456789ABCDEF";

    /// <summary>Whether this is an https:// URL, whose connection runs TLS.</summary>
    public bool IsSecure { get; }

    /// <summary>The host name or address, an IPv6 literal without its brackets.</summary>
    public string Host { get; }

    /// <summary>The TCP port to connect to.</summary>
    public int Port { get; }

    /// <summary>The path and query the request line names: at least <c>/</c>, percent-encoded where it has to be.</summary>
    public string Target { get; }

    /// <summary>The host, and the port when it is not the scheme's default one: what the Host header names.</summary>
    public string Authority { get; }

    private HttpUrl(bool isSecure, string host, int port, string target)
    {
        IsSecure = isSecure;
        Host = host;
        Port = port;
        Target = target;

        string name = host.Contains(':') ? "[" + host + "]" : host;
        Authority = port == (isSecure ? DefaultSecurePort : DefaultPort) ? name : $"{name}:{port}";
    }

    /// <summary><c>http</c> or <c>https</c>.</summary>
    public string Scheme => IsSecure ? "https" : "http";

    public override string ToString() => Scheme + "://" + Authority + Target;

    /// <summary>
    /// Takes apart an absolute URL. One without a scheme is an http:// URL, as
    /// wget takes it.
    /// </summary>
    /// <exception cref="NotSupportedException">The URL is neither an http:// nor an https:// one, or it carries credentials.</exception>
    /// <exception cref="FormatException">The URL names no host, or a port that is not a TCP port.</exception>
    public static HttpUrl Parse(string url)
    {
        string rest = url.Trim();

        int fragment = rest.IndexOf('#');
        if (fragment >= 0)
        {
            rest = rest.Substring(0, fragment);
        }

        bool isSecure = false;
        int schemeLength = SchemeLength(rest);
        if (schemeLength > 0)
        {
            string scheme = rest.Substring(0, schemeLength);
            isSecure = scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
            if (!isSecure && !scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                throw new NotSupportedException($"{url} is neither an http:// nor an https:// URL.");
            }

            rest = rest.Substring(schemeLength + 3);
        }

        int authorityEnd = rest.IndexOfAny(['/', '?']);
        string authority = authorityEnd < 0 ? rest : rest.Substring(0, authorityEnd);
        string target = authorityEnd < 0 ? "/" : rest.Substring(authorityEnd);

        if (authority.Contains('@'))
        {
            throw new NotSupportedException($"{url} carries credentials, which are not supported.");
        }

        string host;
        string? portText = null;
        if (authority.StartsWith('['))
        {
            int close = authority.IndexOf(']');
            if (close < 0)
            {
                throw new FormatException($"{url} has an IPv6 address with no closing bracket.");
            }

            host = authority.Substring(1, close - 1);
            string afterHost = authority.Substring(close + 1);
            if (afterHost.Length > 0)
            {
                if (afterHost[0] != ':')
                {
                    throw new FormatException($"{url} has something other than a port after its IPv6 address.");
                }

                portText = afterHost.Substring(1);
            }
        }
        else
        {
            int colon = authority.IndexOf(':');
            host = colon < 0 ? authority : authority.Substring(0, colon);
            portText = colon < 0 ? null : authority.Substring(colon + 1);
        }

        if (host.Length == 0)
        {
            throw new FormatException($"{url} names no host.");
        }

        // An empty port ("host:/") is the default one (RFC 3986, section 3.2.3).
        int port = isSecure ? DefaultSecurePort : DefaultPort;
        if (!string.IsNullOrEmpty(portText)
            && (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535))
        {
            throw new FormatException($"{url} names port {portText}, which is not a TCP port.");
        }

        if (target.StartsWith('?'))
        {
            target = "/" + target;
        }

        return new HttpUrl(isSecure, host, port, EncodeTarget(target));
    }

    /// <summary>
    /// Resolves the Location of a redirect against this URL: an absolute URL,
    /// a URL without a scheme (<c>//host/path</c>, which keeps this URL's
    /// scheme), an absolute path, a query, or a path relative to this URL's
    /// directory.
    /// </summary>
    /// <exception cref="NotSupportedException">The location is an absolute URL <see cref="Parse"/> does not support.</exception>
    /// <exception cref="FormatException">The location is an absolute URL <see cref="Parse"/> cannot take apart.</exception>
    public HttpUrl Resolve(string location)
    {
        string reference = location.Trim();

        if (SchemeLength(reference) > 0)
        {
            return Parse(reference);
        }

        if (reference.StartsWith("//", StringComparison.Ordinal))
        {
            return Parse(Scheme + ":" + reference);
        }

        int fragment = reference.IndexOf('#');
        if (fragment >= 0)
        {
            reference = reference.Substring(0, fragment);
        }

        if (reference.Length == 0)
        {
            return this;
        }

        string path = Target;
        int query = path.IndexOf('?');
        if (query >= 0)
        {
            path = path.Substring(0, query);
        }

        string target = reference[0] switch
        {
            '/' => reference,
            '?' => path + reference,
            // The target always starts with '/', so there is a directory to resolve against.
            _ => path.Substring(0, path.LastIndexOf('/') + 1) + reference,
        };

        return new HttpUrl(IsSecure, Host, Port, EncodeTarget(target));
    }

    /// <summary>
    /// The length of the scheme <paramref name="url"/> starts with, when it
    /// starts with <c>scheme://</c> (RFC 3986, section 3.1); otherwise 0.
    /// </summary>
    private static int SchemeLength(string url)
    {
        int end = url.IndexOf("://", StringComparison.Ordinal);
        if (end <= 0)
        {
            return 0;
        }

        for (int i = 0; i < end; i++)
        {
            char c = url[i];
            bool valid = char.IsAsciiLetter(c) || (i > 0 && (char.IsAsciiDigit(c) || c is '+' or '-' or '.'));
            if (!valid)
            {
                return 0;
            }
        }

        return end;
    }

    /// <summary>
    /// Percent-encodes what a request line cannot carry as is: spaces, control
    /// characters and anything beyond ASCII, as UTF-8. What is already
    /// percent-encoded is left alone.
    /// </summary>
    private static string EncodeTarget(string target)
    {
        bool clean = true;
        foreach (char c in target)
        {
            if (c <= ' ' || c > '~')
            {
                clean = false;
                break;
            }
        }

        if (clean)
        {
            return target;
        }

        StringBuilder encoded = new(target.Length + 16);
        foreach (byte b in Encoding.UTF8.GetBytes(target))
        {
            if (b <= ' ' || b > '~')
            {
                encoded.Append('%').Append(HexDigits[b >> 4]).Append(HexDigits[b & 0xF]);
            }
            else
            {
                encoded.Append((char)b);
            }
        }

        return encoded.ToString();
    }
}
