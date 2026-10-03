// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Cosmos.Network.Http;

/// <summary>
/// One request and its response, over a connection of their own: requests
/// ask the server to close it once it has answered.
/// </summary>
/// <remarks>
/// Written for the Cosmos socket plugs, in a way a desktop runs as well:
/// <list type="bullet">
/// <item>Host names are resolved with <see cref="Dns"/> before connecting:
/// the plugged host name overloads of Connect do not resolve.</item>
/// <item>The socket is read and waited on as <see cref="SocketTransport"/>
/// explains, TLS included: <see cref="TlsTransport"/> never touches it
/// itself.</item>
/// <item>The connection is closed after the <c>try</c>, not in a
/// <c>finally</c>: a Cosmos kernel skips <c>finally</c> blocks while an
/// exception unwinds.</item>
/// </list>
/// </remarks>
internal static class HttpConnection
{
    /// <summary>Sends <paramref name="request"/> to <paramref name="url"/> and reads the response.</summary>
    /// <param name="url">Where to connect.</param>
    /// <param name="request">The request, head and body.</param>
    /// <param name="isHead">Whether the request is a HEAD one, whose response has no body.</param>
    /// <param name="timeout">How long the server may stay silent, in milliseconds.</param>
    /// <param name="roots">The roots an https:// server's certificate must lead to; Mozilla's when <see langword="null"/>.</param>
    /// <param name="validation">Decides whether to go on with an https:// server, when set.</param>
    /// <exception cref="HttpException">The host could not be resolved or reached, the TLS handshake failed, or the response did not come whole.</exception>
    public static HttpResponse Exchange(HttpUrl url, byte[] request, bool isHead, int timeout,
        TrustedRoots? roots, Func<ServerCertificate, bool>? validation)
    {
        IPAddress address = Resolve(url.Host);
        TrustedRoots? trusted = url.IsSecure ? roots ?? LoadMozillaRoots() : null;

        Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        ITransport? transport = null;
        HttpResponse? response = null;
        Exception? failure = null;
        try
        {
            socket.Connect(address, url.Port);
            SocketTransport plain = new(socket);
            transport = plain;

            if (trusted is not null)
            {
                TlsTransport secure = new(plain, url, trusted, validation);
                transport = secure;
                secure.Handshake(timeout);
            }

            transport.Send(request);
            response = Receive(transport, url, isHead, timeout);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        if (transport is not null)
        {
            transport.Close();
        }
        else
        {
            try
            {
                socket.Close();
            }
            catch (Exception)
            {
                // Nothing left to do with a connection that would not close.
            }
        }

        if (failure is HttpException)
        {
            throw failure;
        }

        if (failure is not null)
        {
            // Not narrowed to SocketException: the Cosmos socket plugs report
            // a refused or dropped connection as a bare Exception.
            string message = transport is not null
                ? $"The connection to {url.Authority} failed: {failure.Message}"
                : $"Could not connect to {url.Authority}: {failure.Message}";
            throw new HttpException(message, failure);
        }

        return response!;
    }

    private static TrustedRoots LoadMozillaRoots()
    {
        try
        {
            return TrustedRoots.Mozilla;
        }
        catch (Exception exception)
        {
            // Only a package built without its roots, or with a damaged copy.
            throw new HttpException($"Could not load the trusted root certificates: {exception.Message}", exception);
        }
    }

    private static IPAddress Resolve(string host)
    {
        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            return literal;
        }

        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(host);
        }
        catch (Exception exception)
        {
            throw new HttpException($"Could not resolve {host}: {exception.Message}", exception);
        }

        // An IPv4 address first: a Cosmos kernel has nothing else to connect to.
        foreach (IPAddress address in addresses)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return address;
            }
        }

        if (addresses.Length == 0)
        {
            throw new HttpException($"Could not resolve {host}: it has no address.");
        }

        return addresses[0];
    }

    private static HttpResponse Receive(ITransport transport, HttpUrl url, bool isHead, int timeout)
    {
        ResponseReader reader = new(isHead);
        byte[] buffer = new byte[SocketTransport.ChunkSize];

        while (!reader.IsComplete)
        {
            int read = transport.Receive(buffer);
            if (read > 0)
            {
                reader.Append(buffer, read);
                continue;
            }

            // The server closed its end.
            if (read < 0)
            {
                break;
            }

            if (Stopwatch.GetElapsedTime(transport.LastActivity).TotalMilliseconds > timeout)
            {
                throw new HttpException($"{url.Authority} sent nothing for {timeout} ms.");
            }
        }

        return reader.ToResponse(url.ToString());
    }
}
