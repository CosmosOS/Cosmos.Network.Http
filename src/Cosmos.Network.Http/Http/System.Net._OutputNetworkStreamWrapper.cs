//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

namespace Cosmos.Network.Http
{
    using System.IO;
    using System.Net.Sockets;
    using System.Text;

    /// <summary>
    /// The OutputNetworkStreamWrapper is used to re-implement calls to  NetworkStream.Write
    /// On first write HttpListenerResponse needs to send HTTP headers to client.
    /// </summary>
    internal class OutputNetworkStreamWrapper : Stream
    {
        /// <summary>
        /// This is a socket connected to client.
        /// OutputNetworkStreamWrapper owns the socket, not NetworkStream.
        /// If connection is persistent, then the m_Socket is transferred to the list of
        /// </summary>
        internal Socket m_Socket;

        /// <summary>
        /// Actual network or SSL stream connected to the client.
        /// It could be SSL stream, so NetworkStream is not exact type, m_Stream would be derived from NetworkStream
        /// </summary>
        internal NetworkStream m_Stream;

        /// <summary>
        /// If true causes all written data to be encoded as chunks
        /// </summary>
        internal bool m_enableChunkedEncoding = false;

        /// <summary>
        /// Cosmos: whether the last chunk was sent, so it is sent once: by Flush, else by HttpListenerResponse.Close.
        /// </summary>
        private bool m_chunksFinished = false;

        /// <summary>
        /// Cosmos: the connection's reader, kept across its requests: what it read ahead of one request is the next's.
        /// nanoFramework made one per request, which dropped it.
        /// </summary>
        internal InputNetworkStreamWrapper m_Input;

        /// <summary>
        /// Cosmos: the body bytes the response wrote, so its Close knows whether it sent what its Content-Length said.
        /// </summary>
        internal long m_BodyWritten;

        /// <summary>
        /// Cosmos: whether the last chunk of a chunked response was sent.
        /// </summary>
        internal bool ChunksFinished => m_chunksFinished;

        /// <summary>
        /// Cosmos: whether bytes of a request wait in the connection's reader, already read from the socket.
        /// </summary>
        internal bool HasBufferedInput => m_Input != null && m_Input.m_dataEnd > m_Input.m_dataStart;

        /// <summary>
        /// Type definition of delegate for sending of HTTP headers.
        /// </summary>
        internal delegate void SendHeadersDelegate();

        /// <summary>
        /// If not null - indicates whether we have sent headers or not.
        /// Calling of delegete sends HTTP headers to client - HttpListenerResponse.SendHeaders()
        /// </summary>
        private SendHeadersDelegate m_headersSend;

        /// <summary>
        /// EOL marker in chunked encoding
        /// </summary>
        private readonly byte[] EOLMarker = { 0xd, 0xa };

        /// <summary>
        /// Just passes parameters to the base.
        /// Socket is not owned by base NetworkStream
        /// </summary>
        /// <param name="socket"></param>
        /// <param name="stream"></param>
        public OutputNetworkStreamWrapper(Socket socket, NetworkStream stream)
        {
            m_Socket = socket;
            m_Stream = stream;
        }

        /// <summary>
        /// Sets the delegate for sending of headers.
        /// </summary>
        internal SendHeadersDelegate HeadersDelegate { set { m_headersSend = value; } }

        /// <summary>
        /// Cosmos: the stream to write to, which is gone once this one is closed (by the handler, or by an Abort on
        /// another thread): an ObjectDisposedException then, where nanoFramework dereferences null, a kernel panic on
        /// Cosmos.
        /// </summary>
        private NetworkStream Target
        {
            get
            {
                NetworkStream stream = m_Stream;
                if (stream == null)
                {
                    throw new ObjectDisposedException(nameof(OutputNetworkStreamWrapper));
                }

                return stream;
            }
        }

        /// <summary>
        /// Return true if stream support reading.
        /// </summary>
        public override bool CanRead { get { return false; } }

        /// <summary>
        /// Return true if stream supports seeking
        /// </summary>
        public override bool CanSeek { get { return false; } }

        /// <summary>
        /// Return true if timeout is applicable to the stream
        /// </summary>
        public override bool CanTimeout { get { return Target.CanTimeout; } }

        /// <summary>
        /// Return true if stream support writing. It should be true, as this is output stream.
        /// </summary>
        public override bool CanWrite { get { return true; } }

        /// <summary>
        /// Gets the length of the data available on the stream.
        /// Since this is output stream reading is not allowed and length does not have meaning.
        /// </summary>
        /// <returns>The length of the data available on the stream.</returns>
        public override long Length { get { throw new NotSupportedException(); } }

        /// <summary>
        /// Position is not supported for NetworkStream
        /// </summary>
        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Timeout for read operations.
        /// </summary>
        public override int ReadTimeout
        {
            get { return Target.ReadTimeout; }
            set { Target.ReadTimeout = value; }
        }

        /// <summary>
        /// Timeout for write operations.
        /// </summary>
        public override int WriteTimeout
        {
            get { return Target.WriteTimeout; }
            set { Target.WriteTimeout = value; }
        }

        /// <summary>
        /// Writes to stream size of chunk and marks start of the chunk 
        /// </summary>
        private void WriteChunkStart(int size)
        {
            byte[] chunkLengthBytes = Encoding.UTF8.GetBytes($"{size:X}");
            Target.Write(chunkLengthBytes, 0, chunkLengthBytes.Length);
            Target.Write(EOLMarker, 0, EOLMarker.Length);
        }

        /// <summary>
        /// Writes to stream marker - finish of the chunk
        /// </summary>
        private void WriteChunkEnd()
        {
            Target.Write(EOLMarker, 0, EOLMarker.Length);
        }

        /// <summary>
        /// Cosmos: starts a response on the connection, which may be kept alive after another: not chunked yet.
        /// </summary>
        internal void StartResponse(SendHeadersDelegate headersSend)
        {
            m_headersSend = headersSend;
            m_enableChunkedEncoding = false;
            m_chunksFinished = false;
            m_BodyWritten = 0;
        }

        /// <summary>
        /// Cosmos: sends the last chunk of a chunked response whose headers were sent, unless it was. nanoFramework's
        /// HttpListenerResponse.Close flushes the network stream, not this one, so a chunked response never ended
        /// unless its OutputStream was flushed.
        /// </summary>
        internal void FinishChunks()
        {
            if (m_enableChunkedEncoding && !m_chunksFinished && m_headersSend == null && m_Stream != null)
            {
                m_chunksFinished = true;
                WriteChunkFinish();
            }
        }

        /// <summary>
        /// Writes to stream marker - finish of all chunks
        /// </summary>
        private void WriteChunkFinish()
        {
            byte[] zero = { 0x30 };
            Target.Write(zero, 0, 1);
            Target.Write(EOLMarker, 0, EOLMarker.Length);
            Target.Write(EOLMarker, 0, EOLMarker.Length);
        }

        /// <summary>
        /// Closes the stream. Verifies that HTTP response is sent before closing.
        /// </summary>
        public override void Close()
        {
            if (m_headersSend != null)
            {
                // Calls HttpListenerResponse.SendHeaders. HttpListenerResponse.SendHeaders sets m_headersSend to null.
                // Cosmos: the connection closed even when the client is gone, which nanoFramework left open.
                try
                {
                    m_headersSend();
                }
                catch
                {
                    m_headersSend = null;
                }
            }

            if (m_Stream != null) m_Stream.Close();
            m_Stream = null;
            m_Socket = null;
        }

        /// <summary>
        /// Flushes the stream. Verifies that HTTP response is sent before flushing.
        /// </summary>
        public override void Flush()
        {
            if (m_headersSend != null)
            {
                // Calls HttpListenerResponse.SendHeaders. HttpListenerResponse.SendHeaders sets m_headersSend to null.
                m_headersSend();
            }

            FinishChunks();

            // Need to check for null before using here
            m_Stream?.Flush();
        }

        /// <summary>
        /// This putput stream, so read is not supported.
        /// </summary>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// This putput stream, so read is not supported.
        /// </summary>
        /// <returns></returns>
        public override int ReadByte()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Seeking is not suported on network streams
        /// </summary>
        /// <param name="offset">Offset to seek</param>
        /// <param name="origin">Relative origin of the seek</param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Setting length is not suported on network streams
        /// </summary>
        /// <param name="value">Length to set</param>
        /// <returns></returns>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Writes single byte to the stream.
        /// </summary>
        /// <param name="value">Byte value to write.</param>
        public override void WriteByte(byte value)
        {
            if (m_headersSend != null)
            {
                // Calls HttpListenerResponse.SendHeaders. HttpListenerResponse.SendHeaders sets m_headersSend to null.
                m_headersSend();
            }

            if (m_enableChunkedEncoding)
            {
                WriteChunkStart(1);
            }

            m_BodyWritten++;
            Target.WriteByte(value);

            if (m_enableChunkedEncoding)
            {
                WriteChunkEnd();
            }
        }


        /// <summary>
        /// Re-implements writing of data to network stream.
        /// The only functionality - on first write it sends HTTP headers.
        /// Then calls base
        /// </summary>
        /// <param name="buffer">Buffer with data to write to HTTP client</param>
        /// <param name="offset">Offset at which to use data from buffer</param>
        /// <param name="size">Count of bytes to write.</param>
        public override void Write(byte[] buffer, int offset, int size)
        {
            // Cosmos: a chunk of 0 bytes is the last one.
            if (size == 0 && m_enableChunkedEncoding)
            {
                return;
            }

            if (m_headersSend != null)
            {
                // Calls HttpListenerResponse.SendHeaders. HttpListenerResponse.SendHeaders sets m_headersSend to null.
                m_headersSend();
            }

            if (m_enableChunkedEncoding)
            {
                WriteChunkStart(size);
            }

            m_BodyWritten += size;
            Target.Write(buffer, offset, size);

            if (m_enableChunkedEncoding)
            {
                WriteChunkEnd();
            }
        }

        public override int Read(Span<byte> buffer)
        {
            throw new NotSupportedException();
        }
    }
}
