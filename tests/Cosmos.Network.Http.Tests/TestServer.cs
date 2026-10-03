// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// A loopback server that answers each connection with the next handler a
/// test queued, so a test writes the response bytes exactly as a server
/// would send them.
/// </summary>
internal sealed class TestServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Thread _thread;
    private readonly ConcurrentQueue<Action<TestConnection>> _handlers = new();
    private volatile bool _disposed;

    public TestServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _thread = new Thread(Serve) { IsBackground = true };
        _thread.Start();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>The requests received, in order.</summary>
    public ConcurrentQueue<TestRequest> Requests { get; } = new();

    /// <summary>The first failure of a handler, rethrown by <see cref="Dispose"/> so the test sees it.</summary>
    private Exception? _failure;

    public string Url(string target) => $"http://127.0.0.1:{Port}{target}";

    /// <summary>Queues the handler for the next connection.</summary>
    public TestServer Then(Action<TestConnection> handler)
    {
        _handlers.Enqueue(handler);
        return this;
    }

    /// <summary>Queues a handler that reads the request and sends <paramref name="response"/>, then closes.</summary>
    public TestServer Then(string response) => Then(connection =>
    {
        connection.ReadRequest();
        connection.Write(response);
    });

    public void Dispose()
    {
        _disposed = true;
        _listener.Stop();
        _thread.Join(5000);
        if (_failure is not null)
        {
            throw new InvalidOperationException("A test server handler failed.", _failure);
        }
    }

    private void Serve()
    {
        while (!_disposed)
        {
            TcpClient client;
            try
            {
                client = _listener.AcceptTcpClient();
            }
            catch (SocketException)
            {
                return;
            }

            using (client)
            {
                if (!_handlers.TryDequeue(out Action<TestConnection>? handler))
                {
                    continue;
                }

                try
                {
                    handler(new TestConnection(this, client));
                }
                catch (Exception exception) when (exception is IOException or SocketException)
                {
                    // The client went away, which some tests make it do.
                }
                catch (Exception exception)
                {
                    _failure ??= exception;
                }
            }
        }
    }

    internal void Record(TestRequest request) => Requests.Enqueue(request);
}

/// <summary>A request as the test server received it.</summary>
internal sealed record TestRequest(string Method, string Target, Dictionary<string, string> Headers, byte[] Body, string Head);

/// <summary>One connection to the test server.</summary>
internal sealed class TestConnection
{
    private readonly TestServer _server;
    private readonly NetworkStream _stream;
    private readonly MemoryStream _pending = new();

    public TestConnection(TestServer server, TcpClient client)
    {
        _server = server;
        _stream = client.GetStream();
        _stream.ReadTimeout = 10_000;
    }

    /// <summary>Reads a request head and the body its Content-Length announces.</summary>
    public TestRequest ReadRequest()
    {
        byte[] buffer = new byte[4096];
        int headEnd;
        while ((headEnd = IndexOfHeadEnd(_pending.GetBuffer(), (int)_pending.Length)) < 0)
        {
            int read = _stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                throw new IOException("The client closed before sending a whole head.");
            }

            _pending.Write(buffer, 0, read);
        }

        string head = Encoding.UTF8.GetString(_pending.GetBuffer(), 0, headEnd);
        string[] lines = head.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        string[] requestLine = lines[0].Split(' ');
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');
            headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
        }

        int length = headers.TryGetValue("Content-Length", out string? value) ? int.Parse(value) : 0;
        while (_pending.Length < headEnd + length)
        {
            int read = _stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                throw new IOException("The client closed before sending a whole body.");
            }

            _pending.Write(buffer, 0, read);
        }

        byte[] body = new byte[length];
        Buffer.BlockCopy(_pending.GetBuffer(), headEnd, body, 0, length);

        TestRequest request = new(requestLine[0], requestLine[1], headers, body, head);
        _server.Record(request);
        return request;
    }

    public void Write(string text) => Write(Encoding.UTF8.GetBytes(text));

    public void Write(byte[] data)
    {
        _stream.Write(data, 0, data.Length);
        _stream.Flush();
    }

    /// <summary>Writes <paramref name="text"/> a byte at a time, so the client sees every split there is.</summary>
    public void WriteSlowly(string text)
    {
        foreach (byte b in Encoding.UTF8.GetBytes(text))
        {
            _stream.WriteByte(b);
            _stream.Flush();
            Thread.Sleep(1);
        }
    }

    /// <summary>Keeps the connection open until the client closes it, as a server that ignores Connection: close would.</summary>
    public void WaitForClientClose()
    {
        byte[] buffer = new byte[256];
        while (_stream.Read(buffer, 0, buffer.Length) > 0)
        {
        }
    }

    /// <summary>Stays silent until the client gives up.</summary>
    public void Hang() => WaitForClientClose();

    private static int IndexOfHeadEnd(byte[] data, int length)
    {
        for (int i = 0; i + 3 < length; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
            {
                return i + 4;
            }
        }

        return -1;
    }
}
