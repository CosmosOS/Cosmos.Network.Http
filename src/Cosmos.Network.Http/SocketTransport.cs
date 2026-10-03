// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Diagnostics;
using System.Net.Sockets;

namespace Cosmos.Network.Http;

/// <summary>The bytes of a request and its response, as they cross the connection: plain, or through TLS.</summary>
internal interface ITransport
{
    /// <summary>When bytes last went through the connection, either way, as a <see cref="Stopwatch"/> timestamp.</summary>
    long LastActivity { get; }

    /// <summary>Sends all of <paramref name="data"/>.</summary>
    void Send(byte[] data);

    /// <summary>
    /// Takes what has arrived into <paramref name="buffer"/>, waiting a
    /// little where the socket can wait.
    /// </summary>
    /// <returns>How many bytes were taken; 0 when none have arrived yet; -1 once the server has closed the connection and everything it sent was taken.</returns>
    int Receive(byte[] buffer);

    /// <summary>Closes the connection, without failing: the server may be gone already.</summary>
    void Close();
}

/// <summary>
/// A TCP connection, used as the Cosmos socket plugs allow:
/// <list type="bullet">
/// <item>Bytes come in through the <c>byte[]</c> Receive overload, for what
/// <see cref="Socket.Available"/> reports: the Span overloads lose what they
/// receive, and a Receive with nothing waiting returns 0 on an open
/// connection.</item>
/// <item>The waiting is done by <see cref="Socket.Poll(int, SelectMode)"/>,
/// never by <c>Thread.Sleep</c>. Poll blocks for its timeout where sockets
/// block, and returns at once on a Cosmos kernel: a request may run on any
/// thread there, the kernel's main loop included, which must never
/// block.</item>
/// </list>
/// </summary>
internal sealed class SocketTransport : ITransport
{
    /// <summary>The most taken from the socket at a time, in bytes.</summary>
    public const int ChunkSize = 16 * 1024;

    /// <summary>How long a Poll waits for data where it can wait, in microseconds.</summary>
    private const int PollIntervalUs = 10_000;

    private readonly Socket _socket;

    /// <summary>Wraps a socket that is connected.</summary>
    public SocketTransport(Socket socket)
    {
        _socket = socket;
        LastActivity = Stopwatch.GetTimestamp();
    }

    public long LastActivity { get; private set; }

    public void Send(byte[] data) => Send(data, data.Length);

    /// <summary>Sends the first <paramref name="count"/> bytes of <paramref name="data"/>.</summary>
    public void Send(byte[] data, int count)
    {
        int sent = 0;
        while (sent < count)
        {
            int written = _socket.Send(data, sent, count - sent, SocketFlags.None);
            if (written <= 0)
            {
                throw new HttpException("The server closed the connection before the request was sent.");
            }

            sent += written;
            LastActivity = Stopwatch.GetTimestamp();
        }
    }

    public int Receive(byte[] buffer)
    {
        int available = _socket.Available;
        if (available > 0)
        {
            int read = _socket.Receive(buffer, 0, Math.Min(available, buffer.Length), SocketFlags.None);
            if (read > 0)
            {
                LastActivity = Stopwatch.GetTimestamp();
                return read;
            }
        }

        // Readable with nothing to read: the server closed its end.
        if (_socket.Poll(PollIntervalUs, SelectMode.SelectRead) && _socket.Available == 0)
        {
            return -1;
        }

        return 0;
    }

    public void Close()
    {
        try
        {
            _socket.Close();
        }
        catch (Exception)
        {
            // Nothing left to do with a connection that would not close.
        }
    }
}
