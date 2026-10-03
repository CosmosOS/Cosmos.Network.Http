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
/// <item>Bytes come in through the <c>byte[]</c> Receive overload, for what
/// <see cref="Socket.Available"/> reports: the Span overloads lose what they
/// receive, and a Receive with nothing waiting returns 0 on an open
/// connection.</item>
/// <item>The waiting is done by <see cref="Socket.Poll(int, SelectMode)"/>,
/// never by <c>Thread.Sleep</c>. Poll blocks for its timeout where sockets
/// block, and returns at once on a Cosmos kernel: a request may run on any
/// thread there, the kernel's main loop included, which must never
/// block.</item>
/// <item>The socket is closed after the <c>try</c>, not in a <c>finally</c>:
/// a Cosmos kernel skips <c>finally</c> blocks while an exception
/// unwinds.</item>
/// </list>
/// </remarks>
internal static class HttpConnection
{
    /// <summary>The most taken from the socket at a time, in bytes.</summary>
    private const int ReceiveChunkSize = 16 * 1024;

    /// <summary>How long a Poll waits for data where it can wait, in microseconds.</summary>
    private const int PollIntervalUs = 10_000;

    /// <summary>Sends <paramref name="request"/> to <paramref name="url"/> and reads the response.</summary>
    /// <param name="url">Where to connect.</param>
    /// <param name="request">The request, head and body.</param>
    /// <param name="isHead">Whether the request is a HEAD one, whose response has no body.</param>
    /// <param name="timeout">How long the server may stay silent, in milliseconds.</param>
    /// <exception cref="HttpException">The host could not be resolved or reached, or the response did not come whole.</exception>
    public static HttpResponse Exchange(HttpUrl url, byte[] request, bool isHead, int timeout)
    {
        IPAddress address = Resolve(url.Host);

        Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        HttpResponse? response = null;
        Exception? failure = null;
        bool connected = false;
        try
        {
            socket.Connect(address, url.Port);
            connected = true;
            Send(socket, request);
            response = Receive(socket, url, isHead, timeout);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        try
        {
            socket.Close();
        }
        catch (Exception)
        {
            // Nothing left to do with a connection that would not close.
        }

        if (failure is HttpException)
        {
            throw failure;
        }

        if (failure is not null)
        {
            // Not narrowed to SocketException: the Cosmos socket plugs report
            // a refused or dropped connection as a bare Exception.
            string message = connected
                ? $"The connection to {url.Authority} failed: {failure.Message}"
                : $"Could not connect to {url.Authority}: {failure.Message}";
            throw new HttpException(message, failure);
        }

        return response!;
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

    private static void Send(Socket socket, byte[] request)
    {
        int sent = 0;
        while (sent < request.Length)
        {
            int count = socket.Send(request, sent, request.Length - sent, SocketFlags.None);
            if (count <= 0)
            {
                throw new HttpException("The server closed the connection before the request was sent.");
            }

            sent += count;
        }
    }

    private static HttpResponse Receive(Socket socket, HttpUrl url, bool isHead, int timeout)
    {
        ResponseReader reader = new(isHead);
        byte[] buffer = new byte[ReceiveChunkSize];
        long lastReceived = Stopwatch.GetTimestamp();

        while (!reader.IsComplete)
        {
            int available = socket.Available;
            if (available > 0)
            {
                int read = socket.Receive(buffer, 0, Math.Min(available, buffer.Length), SocketFlags.None);
                if (read > 0)
                {
                    reader.Append(buffer, read);
                    lastReceived = Stopwatch.GetTimestamp();
                    continue;
                }
            }

            // Readable with nothing to read: the server closed its end.
            if (socket.Poll(PollIntervalUs, SelectMode.SelectRead) && socket.Available == 0)
            {
                break;
            }

            if (Stopwatch.GetElapsedTime(lastReceived).TotalMilliseconds > timeout)
            {
                throw new HttpException($"{url.Authority} sent nothing for {timeout} ms.");
            }
        }

        return reader.ToResponse(url.ToString());
    }
}
