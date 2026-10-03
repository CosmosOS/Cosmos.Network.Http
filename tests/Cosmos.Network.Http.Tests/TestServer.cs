// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// A loopback server that answers each connection with the next handler a
/// test queued, so a test writes the response bytes exactly as a server
/// would send them. Given a certificate, it speaks TLS (the desktop's
/// SslStream) before handing the connection over.
/// </summary>
internal sealed class TestServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Thread _thread;
    private readonly ConcurrentQueue<Action<TestConnection>> _handlers = new();
    private readonly SslStreamCertificateContext? _certificate;
    private readonly SslProtocols _protocols;
    private volatile bool _disposed;

    /// <param name="certificate">The certificate, and the chain, to speak TLS with; plain HTTP without one.</param>
    /// <param name="protocols">The TLS versions to accept: the system's choice by default.</param>
    public TestServer(SslStreamCertificateContext? certificate = null, SslProtocols protocols = SslProtocols.None)
    {
        _certificate = certificate;
        _protocols = protocols;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _thread = new Thread(Serve) { IsBackground = true };
        _thread.Start();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>The requests received, in order.</summary>
    public ConcurrentQueue<TestRequest> Requests { get; } = new();

    /// <summary>The TLS handshakes completed, in order: the server name the client asked for, and what was agreed on.</summary>
    public ConcurrentQueue<TestHandshake> Handshakes { get; } = new();

    /// <summary>The first failure of a handler, rethrown by <see cref="Dispose"/> so the test sees it.</summary>
    private Exception? _failure;

    public string Url(string target, string host = "127.0.0.1") =>
        $"{(_certificate is null ? "http" : "https")}://{host}:{Port}{target}";

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
                    handler(new TestConnection(this, client, Secure(client)));
                }
                catch (Exception exception) when (exception is IOException or SocketException or AuthenticationException)
                {
                    // The client went away, which some tests make it do,
                    // refusing the server's certificate among others.
                }
                catch (Exception exception)
                {
                    _failure ??= exception;
                }
            }
        }
    }

    internal void Record(TestRequest request) => Requests.Enqueue(request);

    /// <summary>The connection's stream, after a TLS handshake when the server has a certificate.</summary>
    private Stream Secure(TcpClient client)
    {
        NetworkStream stream = client.GetStream();
        if (_certificate is null)
        {
            return stream;
        }

        SslStream ssl = new(stream);
        ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
        {
            ServerCertificateContext = _certificate,
            EnabledSslProtocols = _protocols,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
        });

        // On a server, TargetHostName is the name the client asked for (SNI).
        string? serverName = ssl.TargetHostName.Length == 0 ? null : ssl.TargetHostName;
        Handshakes.Enqueue(new TestHandshake(serverName, ssl.SslProtocol, ssl.NegotiatedApplicationProtocol.ToString()));
        return ssl;
    }
}

/// <summary>A TLS handshake as the test server saw it.</summary>
internal sealed record TestHandshake(string? ServerName, SslProtocols Protocol, string ApplicationProtocol);

/// <summary>A request as the test server received it.</summary>
internal sealed record TestRequest(string Method, string Target, Dictionary<string, string> Headers, byte[] Body, string Head);

/// <summary>One connection to the test server.</summary>
internal sealed class TestConnection
{
    private readonly TestServer _server;
    private readonly Stream _stream;
    private readonly MemoryStream _pending = new();

    public TestConnection(TestServer server, TcpClient client, Stream stream)
    {
        _server = server;
        client.GetStream().ReadTimeout = 10_000;
        _stream = stream;
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

    /// <summary>Sends TLS close_notify, as a server that closes properly does before closing the connection.</summary>
    public void CloseNotify() => ((SslStream)_stream).ShutdownAsync().GetAwaiter().GetResult();

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
