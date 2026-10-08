//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

namespace Cosmos.Network.Http
{
    using System.Diagnostics;
    using System.IO;
    using System.Net.Sockets;
    using System.Runtime.CompilerServices;
    using System.Threading;

    /// <summary>
    /// The InputNetworkStreamWrapper is used to re-implement calls to  NetworkStream.Read
    /// It has internal buffer and during initial read operation it places available data from socket into buffer.
    /// Later it releases data to Stream.Read calls.
    /// It also provides direct access to buffered data for internal code. 
    /// It provides possibility to "unread" or probe data - meaning user can read byte of data and then return it back to stream.
    /// </summary>
    internal class InputNetworkStreamWrapper : Stream, IKnowWhenDone
    {
        static private System.Text.Decoder UTF8decoder = System.Text.Encoding.UTF8.GetDecoder();
        static private System.Text.Encoding UTF8Encoding = System.Text.Encoding.UTF8;

        /// <summary>
        /// Actual network or SSL stream connected to the server.
        /// It could be SSL stream, so NetworkStream is not exact type, m_Stream would be derived from NetworkStream
        /// </summary>
        internal NetworkStream m_Stream;

        /// <summary>
        /// Last time this stream was used ( used to timeout idle connections ).
        /// </summary>
        internal DateTime m_lastUsed;

        /// <summary>
        /// This is a socket connected to client. 
        /// InputNetworkStreamWrapper owns the socket, not NetworkStream.
        /// If connection is persistent, then the m_Socket is transferred to the list of 
        /// </summary>
        internal Socket m_Socket;

        /// <summary>
        /// Determines is the NetworkStream owns the socket
        /// </summary>
        internal bool m_OwnsSocket;

        /// <summary>
        /// Address and port used for connection of the socket. It is in form of Address:Port ( like www.microsoft.com:80 )
        /// </summary>
        internal string m_rmAddrAndPort;

        /// <summary>
        /// Determines if the stream is currently in use or not.
        /// </summary>
        internal bool m_InUse;

        /// <summary>
        /// Buffer for one line of HTTP header.
        /// </summary>
        private byte[] m_lineBuf;

        /// <summary>
        /// Internal buffer size for read caching
        /// </summary>
        private const int read_buffer_size = 256;

        /// <summary>
        /// Internal buffer for read caching
        /// </summary>
        internal byte[] m_readBuffer;

        /// <summary>
        /// End of valid data in internal buffer.
        /// </summary>
        internal int m_dataEnd;

        /// <summary>
        /// Start of valid data in internal buffer.
        /// </summary>
        internal int m_dataStart;

        /// <summary>
        /// Indicates that the stream has chunking encoding. 
        /// We remove chunk markers and stop reading after end of last chunk.
        /// </summary>
        internal bool m_EnableChunkedDecoding;

        /// <summary>
        /// Chunk data that we are currently decoding.
        /// </summary>
        private Chunk m_chunk;

        /// <summary>
        /// Inidcates the stream wrapper object is a clone and they underlying stream should not be disposed
        /// </summary>
        private bool m_isClone;

        /// <summary>
        /// Cosmos: the stream this one is a clone of, which gets back what the clone read when it is disposed.
        /// </summary>
        private InputNetworkStreamWrapper m_original;

        /// <summary>
        /// Cosmos: counts the responses the connection carried, so a clone of an earlier one gives nothing back.
        /// </summary>
        private int m_generation;

        /// <summary>
        /// Http web responses can contain the Content-Length of the response.  In these cases, we would like the stream to return an EOF indication
        /// if the caller tries to read past the content length. 
        /// </summary>
        internal long m_BytesLeftInResponse;

        /// <summary>
        /// Refills internal buffer from network.
        /// </summary>
        /// <remarks>
        /// Cosmos: not synchronized, as nanoFramework's is: a Cosmos kernel doesn't release the lock while an exception
        /// unwinds, and a read that times out throws. One thread reads a response at a time.
        /// </remarks>
        private int RefillInternalBuffer()
        {
#if DEBUG
            if (m_dataStart != m_dataEnd)
            {
                Debug.WriteLine("Internal ERROR in InputNetworkStreamWrapper");
                m_dataStart = m_dataEnd = 0;
            }
#endif 
            //  m_dataStart should be equal to m_dataEnd. Purge buffered data.
            m_dataStart = m_dataEnd = 0;
            // Read up to read_buffer_size, but less data can be read.
            // This function does not try to block, so it reads available data or 1 byte at least.
            int readCount = ReadableLength(m_Stream);
            if (readCount > read_buffer_size)
            {
                readCount = read_buffer_size;
            }
            else if (readCount == 0)
            {
                readCount = 1;
            }

            m_dataEnd = m_Stream.Read(m_readBuffer, 0, readCount);

            return m_dataEnd;
        }

        /// <summary>
        /// Cosmos: what nanoFramework's NetworkStream.Length is, the number of bytes the stream can return without
        /// waiting, where .NET's Length throws: what the socket holds, or the decrypted bytes of an SslStream.
        /// </summary>
        private static int ReadableLength(NetworkStream stream)
        {
            return stream is SslStream ? (int)stream.Length : stream.Socket.Available;
        }

        /// <summary>
        /// Resets position in internal buffers to zeroes.
        /// </summary>
        internal void ResetState()
        {
            m_dataStart = m_dataEnd = 0;
            m_EnableChunkedDecoding = false;
            m_chunk = null;

            // Cosmos: the end of the previous response, which a clone gives back (see TakeReadState).
            IsDone = false;
            m_generation++;
        }

        /// <summary>
        /// Passes socket parameter to the base.
        /// Base Network stream never owns the stream. 
        /// Socket is directly closed by class that contains InputNetworkStreamWrapper or transferred to
        /// list of idle sockets.
        /// </summary>
        /// <param name="stream">TBD</param>
        /// <param name="socket">TBD</param>
        /// <param name="ownsSocket">TBD</param>
        /// <param name="rmAddrAndPort">TBD</param>
        internal InputNetworkStreamWrapper(NetworkStream stream, Socket socket, bool ownsSocket, string rmAddrAndPort)
        {
            m_Stream = stream;
            m_Socket = socket;
            m_OwnsSocket = ownsSocket;
            m_rmAddrAndPort = rmAddrAndPort;
            m_InUse = true;
            // Cosmos: when it was lent, as CheckPersistentConnections reads it.
            m_lastUsed = DateTime.UtcNow;
            // negative value indicates no length is set, in which case we will continue to read upon the callers request
            m_BytesLeftInResponse = -1;

            // Start with 80 (0x50) byte buffer for string. If string longer, we double it each time.
            m_lineBuf = new byte[0x50];
            m_readBuffer = new byte[read_buffer_size];
        }

        /// <summary>
        /// Re-implements reading of data to network stream.
        /// </summary>
        /// <param name="buffer">Buffer with data to write to HTTP client</param>
        /// <param name="offset">Offset at which to use data from buffer</param>
        /// <param name="size">Count of bytes to write.</param>
        public override int Read(byte[] buffer, int offset, int size)
        {
            // If chunking decoding is not needed - perform normal read.
            if (!m_EnableChunkedDecoding)
            {
                return ReadInternal(buffer, offset, size);
            }

            // With chunking decoding there are 4 cases:
            // 1. We are at the beginning of chunk. Then we read chunk header and fill m_chunk.
            // 2. We are in the middle of chunk. Then it is kind of normal read, but no more than chunk length.
            // 3. We are close to the end of chunk. Then we read maximum of data in the chunk and set m_chunk to null.
            // 4. We already read last chunk of zero size. Return with zero bytes read. 
            if (m_chunk == null)
            {
                // We are in the beginnig of the chunk. Create new chunk and continue. This is case 1. 
                m_chunk = GetChunk();
            }

            // First validate that chunk is more than zero in size. The last chunk is zero size and it indicates end of data.
            if (m_chunk.m_Size == 0)
            {
                // Nothing to read and actually it is the end of the message body. It is "case 4".
                IsDone = true;
                return 0;
            }

            // Check if request to read is larger than remaining data in the chunk.
            if (size > m_chunk.m_Size - m_chunk.m_OffsetIntoChunk)
            {
                // We set size to the maximum data remaining the the chunk. This is the case 3.
                size = (int)(m_chunk.m_Size - m_chunk.m_OffsetIntoChunk);
            }

            // Ok, we know that we are in process of reading chunk data. This is case 2. 
            // size is already adjusted to the maximum data remaining in the chunk.
            int retVal = ReadInternal(buffer, offset, size);

            // Adjust offset into chunk by amount of data read. retVal could be less than size.
            m_chunk.m_OffsetIntoChunk += (uint)retVal;

            // If we reached end of chunk, then set m_chunk to null. This indicates that chunk was completed.
            if (m_chunk.m_OffsetIntoChunk == m_chunk.m_Size)
            {
                m_chunk = null;
            }

            return retVal;
        }

        /// <summary>
        /// Clears the read buffer and reads from the underlying stream until no more data is available.
        /// </summary>
        public void FlushReadBuffer()
        {
            byte[] buffer = new byte[1024];

            // Cosmos: drops what can be read without waiting, where nanoFramework waits up to a second in Socket.Poll
            // for more and reads the socket's Available, which counts encrypted bytes for https and would leave Read
            // waiting for a record that never comes; ReadableLength counts what the stream can return.
            // What was read ahead belongs to the response.
            if (m_BytesLeftInResponse > 0) m_BytesLeftInResponse -= Math.Min(m_dataEnd - m_dataStart, m_BytesLeftInResponse);

            try
            {
                int avail = ReadableLength(m_Stream);

                while (avail > 0)
                {
                    int bytes = m_Stream.Read(buffer, 0, avail > buffer.Length ? buffer.Length : avail);

                    if (bytes <= 0) break;

                    if (m_BytesLeftInResponse > 0) m_BytesLeftInResponse -= bytes;

                    avail = ReadableLength(m_Stream);
                }
            }
            catch
            {
            }

            // Cosmos: whether the whole response was read, which nanoFramework's wait for the rest of it makes likely.
            m_ResponseComplete = m_BytesLeftInResponse == 0 || (m_EnableChunkedDecoding && IsDone);

            m_dataEnd = m_dataStart = 0;
            m_BytesLeftInResponse = -1;
        }

        // Cosmos: set by FlushReadBuffer.
        private bool m_ResponseComplete;

        private void ReleaseThread()
        {
            FlushReadBuffer();

            // Cosmos: a connection with part of a response still to come can't carry the next request.
            if (!m_ResponseComplete)
            {
                HttpWebRequest.RemoveStreamFromPool(this);
                Dispose();
                return;
            }

            m_lastUsed = DateTime.UtcNow;
            ResetState();

            m_InUse = false;
        }

        ///
        /// Flushes the read buffer and resets the streams parameters.  When in used in conjunction with the HttpWebRequest class
        /// this method enables this stream to be re-used.
        ///
        public void ReleaseStream()
        {
            // Cosmos: on the calling thread, which FlushReadBuffer no longer holds; nanoFramework starts a thread for
            // each response, and a Cosmos kernel never frees a thread's stack.
            ReleaseThread();
        }

        /// <summary>
        /// Re-implements reading of data to network stream.
        /// </summary>
        /// <param name="buffer">Buffer with data to write to HTTP client</param>
        /// <param name="offset">Offset at which to use data from buffer</param>
        /// <param name="size">Count of bytes to write.</param>
        public int ReadInternal(byte[] buffer, int offset, int size)
        {
            // Need to init return value to zero explicitly, otherwise warning generated.
            int retVal = 0;

            // Cosmos: the end of a body of known length, or of a response without one (HEAD, 1xx, 204, 304), where
            // nanoFramework would go on to return what follows it: the next response on a kept-alive connection.
            if (m_BytesLeftInResponse == 0)
            {
                IsDone = true;
                return 0;
            }

            if (m_BytesLeftInResponse > 0 && size > m_BytesLeftInResponse)
            {
                size = (int)m_BytesLeftInResponse;
            }

            // As first step we copy the buffered data if present
            int dataBuffered = m_dataEnd - m_dataStart;
            if (dataBuffered > 0)
            {
                int dataToCopy = size < dataBuffered ? size : dataBuffered;
                for (int i = 0; i < dataToCopy; i++)
                {
                    buffer[offset + i] = m_readBuffer[m_dataStart + i];
                }
                m_dataStart += dataToCopy;
                offset += dataToCopy;
                size -= dataToCopy;
                retVal += dataToCopy;
            }

            //
            // Now we check if more data is needed.
            // if m_BytesLeftInResponse == -1      , then we don't known the content length of the response
            // if m_BytesLeftInResponse is > retVal, then the data in the internal buffer (above) was less than the 
            //                                                         the total content length of the response stream
            // In either case, we need to read more data to fullfill the read request
            //
            if (size > 0 && (m_BytesLeftInResponse == -1 || m_BytesLeftInResponse > retVal))
            {
                // If buffering desired and requested data is less than internal buffer size
                // then we read into internal buffer. 
                if (size < read_buffer_size)
                {
                    if (0 == RefillInternalBuffer())
                    {
                        // Cosmos: what was copied from the buffer above is returned, where nanoFramework returned 0;
                        // and a body cut short is an error, where it was the end.
                        if (retVal == 0)
                        {
                            ThrowIfCutShort();
                        }

                        // Handle the 'HTTP/1.0' case
                        IsDone = IsHttp1_0Completed();
                        return retVal;
                    }

                    dataBuffered = m_dataEnd - m_dataStart;
                    if (dataBuffered > 0)
                    {
                        int dataToCopy = size < dataBuffered ? size : dataBuffered;
                        for (int i = 0; i < dataToCopy; i++)
                        {
                            buffer[offset + i] = m_readBuffer[m_dataStart + i];
                        }
                        m_dataStart += dataToCopy;
                        offset += dataToCopy;
                        size -= dataToCopy;
                        retVal += dataToCopy;
                    }
                }
                else // Do not replentish internal buffer. Read rest of data directly
                {
                    int bytesRead = m_Stream.Read(buffer, offset, size);

                    // Cosmos: see above.
                    if (bytesRead == 0 && retVal == 0)
                    {
                        ThrowIfCutShort();
                    }

                    retVal += bytesRead;

                    // Handle the 'HTTP/1.0' case                    
                    if ((bytesRead == 0) && IsHttp1_0Completed())
                    {
                        IsDone = true;
                        return retVal;
                    }
                }
            }

            // update the bytes left in response 
            if (m_BytesLeftInResponse > 0)
            {
                m_BytesLeftInResponse -= retVal;

                // in case there were more bytes in the buffer than we expected make sure the next call returns 0
                if (m_BytesLeftInResponse < 0) m_BytesLeftInResponse = 0;

                // Cosmos: the end of the body.
                if (m_BytesLeftInResponse == 0) IsDone = true;
            }

            return retVal;
        }

        /// <summary>
        /// Cosmos: throws when the connection ended before the body did: the rest of a length it gave, or of a chunk.
        /// nanoFramework's StreamContent slept and read again, forever, and a Cosmos one would return the body cut
        /// short as if complete.
        /// </summary>
        private void ThrowIfCutShort()
        {
            if (m_BytesLeftInResponse > 0)
            {
                throw new IOException("The connection was closed " + m_BytesLeftInResponse + " bytes before the end of the body.");
            }

            if (m_EnableChunkedDecoding)
            {
                throw new IOException("The connection was closed before the last chunk of the body.");
            }
        }

        /// <summary>
        /// Returns true if we are in 'HTTP/1.0' mode and the connection has been closed, which marks the end of the body.
        /// </summary>
        /// <remarks>
        /// In 'HTTP/1.0' mode, where the content length is not transmitted in the response header and the server closes the connection to mark the end of the body.
        /// (see: RFC9112, 6.3, point 8, https://www.rfc-editor.org/rfc/rfc9112#name-message-body-length)
        /// </remarks>
        private bool IsHttp1_0Completed()
        {
            return
                (m_BytesLeftInResponse == -1) && !m_EnableChunkedDecoding &&                // We are in HTTP/1.0 mode
                m_Socket.Poll(1, SelectMode.SelectRead) && (m_Socket.Available == 0);       // The socket is disconnected
        }

        /// <summary>
        /// Impletments Write for the stream. 
        /// Since we do not have write buffering, all we do is delegate to the m_Stream. 
        /// </summary>
        /// <param name="buffer">Buffer to write</param>
        /// <param name="offset">Start offset to write data</param>
        /// <param name="count">Count of bytes to write</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            m_Stream.Write(buffer, offset, count);
        }

        /// <summary>
        /// Since we do not have write buffering, all we do is delegate to the m_Stream.
        /// </summary>
        public override void Flush()
        {
            m_Stream.Flush();
        }

        /// <summary>
        /// Return true if stream support reading.
        /// </summary>
        public override bool CanRead { get { return m_Stream.CanRead; } }

        /// <summary>
        /// Return true if stream supports seeking
        /// </summary>
        public override bool CanSeek { get { return m_Stream.CanSeek; } }

        /// <summary>
        /// Return true if timeout is applicable to the stream
        /// </summary>
        public override bool CanTimeout { get { return m_Stream.CanTimeout; } }

        /// <summary>
        /// Return true if stream support writing.
        /// </summary>
        public override bool CanWrite { get { return m_Stream.CanWrite; } }

        /// <summary>
        /// Gets the length of the data available on the stream.
        /// </summary>
        /// <returns>The length of the data available on the stream. 
        /// Add data cached in the stream buffer to available on socket</returns>
        public override long Length { get { return m_EnableChunkedDecoding && m_chunk != null ? m_chunk.m_Size : ReadableLength(m_Stream) + m_dataEnd - m_dataStart; } }

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
        /// Seekking is not suported on network streams
        /// </summary>
        /// <param name="offset">Offset to seek</param>
        /// <param name="origin">Relative origin of the seek</param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Setting of length is not supported
        /// </summary>
        /// <param name="value">Length to set</param>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Timeout for read operations. 
        /// </summary>
        public override int ReadTimeout
        {
            get { return m_Stream.ReadTimeout; }
            set { m_Stream.ReadTimeout = value; }
        }

        /// <summary>
        /// Timeout for write operations.
        /// </summary>
        public override int WriteTimeout
        {
            get { return m_Stream.WriteTimeout; }
            set { m_Stream.WriteTimeout = value; }
        }

        public bool IsDone { get; private set; }

        public Stream CloneStream()
        {
            InputNetworkStreamWrapper clone = this.MemberwiseClone() as InputNetworkStreamWrapper;
            clone.m_isClone = true;
            clone.m_original = this;

            return clone;
        }

        /// <summary>
        /// Cosmos: the next request on a kept-alive connection: its own framing, after what was read ahead of it.
        /// </summary>
        internal void StartRequest()
        {
            m_EnableChunkedDecoding = false;
            m_chunk = null;
            IsDone = false;
            m_BytesLeftInResponse = -1;
            m_generation++;
        }

        /// <summary>
        /// Cosmos: whether the whole body of the message was read: its length, or its last chunk.
        /// </summary>
        internal bool IsBodyRead => m_BytesLeftInResponse == 0 || (m_EnableChunkedDecoding && IsDone);

        /// <summary>
        /// Cosmos: a response begins on the connection: what a clone made before gives back is no longer its state.
        /// </summary>
        internal void StartResponse()
        {
            m_generation++;
        }

        /// <summary>
        /// Cosmos: takes what a clone of this stream read of the response, so ReleaseStream knows whether all of it
        /// was read and the connection can carry another request. nanoFramework reads whatever comes for a second
        /// after a response and reuses the connection anyway.
        /// </summary>
        private void TakeReadState(InputNetworkStreamWrapper clone)
        {
            // Disposed after its response was released: the connection carries another now.
            if (clone.m_generation != m_generation)
            {
                return;
            }

            m_readBuffer = clone.m_readBuffer;
            m_dataStart = clone.m_dataStart;
            m_dataEnd = clone.m_dataEnd;
            m_BytesLeftInResponse = clone.m_BytesLeftInResponse;
            m_chunk = clone.m_chunk;
            IsDone = clone.IsDone;
        }

        /// <summary>
        /// Overrides the Dispose Behavior
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            m_InUse = false;

            // Clones share m_Stream/m_Socket with the original (see CloneStream), so only
            // the original may close them. HttpResponseMessage disposes the original deterministically.
            if (m_isClone)
            {
                // Cosmos: see TakeReadState.
                if (m_original != null)
                {
                    m_original.TakeReadState(this);
                    m_original = null;
                }
            }
            else
            {
                m_Stream.Close();

                if (m_OwnsSocket)
                {
                    m_Socket.Close();
                }
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Reads one line from steam, terminated by \r\n or by \n.
        /// </summary>
        /// <param name="maxLineLength">Maxinun length of the line. If line is longer than maxLineLength exception is thrown</param>
        /// <returns>String that represents the line, not including \r\n or by \n</returns>
        internal string Read_HTTP_Line(int maxLineLength)
        {
            int curPos = 0;
            bool readLineComplete = false;

            while (!readLineComplete)
            {
                // We need to read character by character. For efficiency we need stream that implements internal bufferting.
                // We cannot read more than one character at a time, since this one could be the last.
                int maxCurSize = m_lineBuf.Length - 1;
                maxCurSize = maxCurSize < maxLineLength ? maxCurSize : maxLineLength;
                while (curPos < maxCurSize)
                {
                    // If data available, Reads one byte of data. 
                    if (m_dataEnd - m_dataStart > 0)
                    {   // Very special code for reading of one character.
                        m_lineBuf[curPos] = m_readBuffer[m_dataStart]; ++curPos; ++m_dataStart;
                    }
                    else
                    {   // Refill internal buffer and read one character.
                        if (0 == RefillInternalBuffer())
                        {
                            readLineComplete = true;
                            break;
                        }
                        m_lineBuf[curPos] = m_readBuffer[m_dataStart]; ++curPos; ++m_dataStart;
                    }

                    // Accoring to HTTP spec HTTP headers lines should be separated by "\r\n"
                    // Still spec requires for testing of "\n" only. So we test both
                    if (m_lineBuf[curPos - 1] == '\r' || m_lineBuf[curPos - 1] == '\n')
                    {
                        // Next character should be '\n' if previous was '\r'
                        if (m_lineBuf[curPos - 1] == '\r')
                        {
                            // If data available, Reads one byte of data. 
                            if (m_dataEnd - m_dataStart > 0)
                            {   // Very special code for reading of one character.
                                m_lineBuf[curPos] = m_readBuffer[m_dataStart]; ++curPos; ++m_dataStart;
                            }
                            else
                            {   // Refill internal buffer and read one character.
                                if (0 == RefillInternalBuffer())
                                {
                                    readLineComplete = true;
                                    break;
                                }
                                m_lineBuf[curPos] = m_readBuffer[m_dataStart]; ++curPos; ++m_dataStart;
                            }
                        }
                        readLineComplete = true;
                        break;
                    }
                }

                // If we reached limit of the line size, just throw protocol violation exception.
                if (curPos == maxLineLength)
                {
                    throw new WebException("Line too long", WebExceptionStatus.ServerProtocolViolation);
                }

                // There was no place in the m_lineBuf or end of line reached. 
                if (!readLineComplete)
                {
                    // Need to allocate larger m_lineBuf and copy existing line there.
                    byte[] newLineBuf = new byte[m_lineBuf.Length * 2];
                    // Copy data to new array
                    m_lineBuf.CopyTo(newLineBuf, 0);
                    // Re-assign. Now m_lineBuf is twice as long and keeps the same data.
                    m_lineBuf = newLineBuf;
                }
            }
            // Now we need to convert from byte array to string.
            if (curPos - 2 > 0)
            {
                int byteUsed, charUsed;
                bool completed = false;
                char[] charBuf = new char[curPos - 2];
                UTF8decoder.Convert(m_lineBuf, 0, curPos - 2, charBuf, 0, charBuf.Length, true, out byteUsed, out charUsed, out completed);
                return new string(charBuf);
            }
            else if (curPos == 0)
            {
                throw new SocketException((int)SocketError.ConnectionAborted);
            }

            return "";
        }

        /// <summary>
        /// Preview the byte in the input stream without removing it.
        /// </summary>
        /// <returns>Next byte in the stream.</returns>
        private byte PeekByte()
        {
            // Refills internal buffer if there is no more data
            if (m_dataEnd == m_dataStart)
            {
                if (0 == RefillInternalBuffer()) throw new SocketException((int)SocketError.ConnectionAborted);
            }
            return m_readBuffer[m_dataStart];
        }

        /// <summary>
        /// Returns the byte in the input stream and removes it.
        /// </summary>
        /// <returns>Next byte in the stream.</returns>
        public override int ReadByte()
        {
            // Refills internal buffer if there is no more data
            if (m_dataEnd == m_dataStart)
            {
                if (0 == RefillInternalBuffer()) throw new SocketException((int)SocketError.ConnectionAborted);
            }
            // Very similar to Peek, but moves current position to next byte.
            return m_readBuffer[m_dataStart++];
        }

        /// <summary>
        /// Writes single byte to stream
        /// </summary>
        /// <param name="value"></param>
        public override void WriteByte(byte value)
        {
            m_Stream.WriteByte(value);
        }

        /// <summary>
        /// Reads HTTP header from input stream.
        /// HTTP header can be wrapped on multiple lines.
        /// If next line starts by white space or tab - means it is continuing current header.
        /// Thus we need to use PeekByte() to check next byte without removing it from stream.
        /// </summary>
        /// <param name="maxLineLength">Maximum length of the header</param>
        /// <returns></returns>
        internal string Read_HTTP_Header(int maxLineLength)
        {
            string strHeader = Read_HTTP_Line(maxLineLength);
            int headLineLen = strHeader.Length;

            // If line is empty - means the last one. Just return it.
            if (headLineLen == 0)
            {
                return strHeader;
            }

            maxLineLength -= headLineLen;
            // Check next byte in the stream. If it is ' ' or '\t' - next line is continuation of existing header.
            while (maxLineLength > 0)
            {
                byte nextByte = PeekByte();
                // If next byte is not white space or tab, then we are done.
                if (!(nextByte == ' ' || nextByte == '\t'))
                {
                    return strHeader;
                }
                // If we got here - means next line starts by white space or tab. Need to read it and append it.
                string strLine = Read_HTTP_Line(maxLineLength);
                // Decrease by amount of data read
                maxLineLength -= strLine.Length;
                // Adds it to the header.
                strHeader += strLine;
            }
            // If we come here - means HTTP header exceedes maximum length.
            throw new WebException("HTTP header too long", WebExceptionStatus.ServerProtocolViolation);
        }

        /// <summary>
        /// Retrieve information of the chunk. 
        /// </summary>
        /// <returns></returns>
        private Chunk GetChunk()
        {
            Chunk nextChunk = new Chunk();
            bool parsing = true;
            ChunkState state = ChunkState.InitialLF;
            byte[] buffer = new byte[1024];
            byte[] data;
            int dataByte = 0;

            while (parsing)
            {
                int readByte = ReadByte();
                switch (readByte)
                {
                    case 13: //CR
                        if (state == ChunkState.InitialLF)
                            break;

                        data = new byte[dataByte];
                        Array.Copy(buffer, data, dataByte);
                        switch (state)
                        {
                            case ChunkState.Size:
                                nextChunk.m_Size = (uint)Convert.ToInt32(new string(UTF8Encoding.GetChars(data)), 16);
                                dataByte = 0;
                                break;
                            case ChunkState.Value:
                                dataByte = 0;
                                break;
                            default:
                                throw new ProtocolViolationException("Wrong state for CR");
                        }
                        state = ChunkState.LF;
                        break;
                    case 10: //LF
                        switch (state)
                        {

                            case ChunkState.LF:
                                parsing = false;
                                break;
                            case ChunkState.InitialLF:
                                state = ChunkState.Size;
                                break;
                            default:
                                throw new ProtocolViolationException("Incorrectly formated Chunk - Unexpected Line Feed");
                        }
                        break;
                    case 59: // ;
                        if (state == ChunkState.Size)
                        {
                            data = new byte[dataByte];
                            Array.Copy(buffer, data, dataByte);
                            nextChunk.m_Size = (uint)Convert.ToInt32(new string(UTF8Encoding.GetChars(data)), 16);
                            dataByte = 0;
                        }
                        else
                            throw new ProtocolViolationException("Incorrectly formated Chunk");
                        state = ChunkState.Name;
                        break;
                    case 61: // =
                        if (state == ChunkState.Name)
                        {
                            dataByte = 0;
                        }
                        else
                            throw new ProtocolViolationException("Incorrectly formated Chunk");
                        state = ChunkState.Value;
                        break;
                    default:
                        if (state == ChunkState.InitialLF)
                            state = ChunkState.Size;

                        // buffer is fixed-size: a chunk-size line/extension without a CR before it fills
                        // up would otherwise write past the end of the array. Fail cleanly instead.
                        if (dataByte >= buffer.Length)
                        {
                            throw new ProtocolViolationException("Chunk header too long");
                        }

                        buffer[dataByte] = (byte)readByte;
                        dataByte++;
                        if (state == ChunkState.LF)
                            throw new ProtocolViolationException("Unexpected data after Line Feed");
                        break;
                }
            }

            return nextChunk;
        }

        public override int Read(Span<byte> buffer)
        {
            // Cosmos: nanoFramework's SpanByte overload threw; .NET's reads through Read(byte[], int, int), as Stream's does.
            return base.Read(buffer);
        }

        private enum ChunkState
        {
            Size,
            Name,
            Value,
            LF,
            InitialLF
        }

        private class Chunk
        {
            public uint m_Size;
            public uint m_OffsetIntoChunk;
        }

    }
}
