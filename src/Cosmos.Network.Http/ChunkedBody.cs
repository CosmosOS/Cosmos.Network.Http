// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System.IO;

namespace Cosmos.Network.Http;

/// <summary>
/// The chunked transfer coding (RFC 9112, section 7.1): chunks, each after
/// its size in hexadecimal, up to a chunk of size 0 and a trailer section.
/// Chunk extensions and trailers carry nothing a client needs and are
/// skipped.
/// </summary>
internal static class ChunkedBody
{
    /// <summary>
    /// Whether the chunked body that starts at <paramref name="position"/>
    /// has arrived whole: its last chunk and the trailer section that ends it.
    /// <paramref name="position"/> moves past each whole chunk, so the next
    /// call resumes there rather than walking the body again.
    /// </summary>
    /// <exception cref="HttpException">A chunk size is malformed.</exception>
    public static bool FindEnd(byte[] data, int length, ref int position)
    {
        while (true)
        {
            int lineEnd = IndexOfLineEnd(data, position, length);
            if (lineEnd < 0)
            {
                return false;
            }

            int size = ParseSize(data, position, lineEnd);
            if (size == 0)
            {
                // The trailer section: field lines up to an empty one.
                int line = lineEnd + 2;
                while (true)
                {
                    int end = IndexOfLineEnd(data, line, length);
                    if (end < 0)
                    {
                        return false;
                    }

                    if (end == line)
                    {
                        return true;
                    }

                    line = end + 2;
                }
            }

            long next = (long)lineEnd + 2 + size + 2;
            if (next > length)
            {
                return false;
            }

            position = (int)next;
        }
    }

    /// <summary>The data of the chunked body that starts at <paramref name="start"/>, chunk sizes, extensions and trailers left out.</summary>
    /// <exception cref="HttpException">The body ends before its last chunk, or a chunk size is malformed.</exception>
    public static byte[] Decode(byte[] data, int start, int length)
    {
        MemoryStream body = new();
        int position = start;
        while (true)
        {
            int lineEnd = IndexOfLineEnd(data, position, length);
            if (lineEnd < 0)
            {
                throw Truncated();
            }

            int size = ParseSize(data, position, lineEnd);
            if (size == 0)
            {
                return body.ToArray();
            }

            int chunkStart = lineEnd + 2;
            if ((long)chunkStart + size > length)
            {
                throw Truncated();
            }

            body.Write(data, chunkStart, size);
            position = chunkStart + size + 2;
        }
    }

    /// <summary>The size on a chunk line, ignoring the extensions after it.</summary>
    private static int ParseSize(byte[] data, int start, int end)
    {
        int size = 0;
        int digits = 0;
        int i = start;
        for (; i < end; i++)
        {
            int digit = HexValue(data[i]);
            if (digit < 0)
            {
                break;
            }

            if (size > (int.MaxValue >> 4))
            {
                throw new HttpException("The response has a chunk larger than 2 GB.");
            }

            size = (size << 4) | digit;
            digits++;
        }

        // What follows the digits, if anything, is whitespace or a ";name=value" extension.
        if (digits == 0 || (i < end && data[i] is not ((byte)';' or (byte)' ' or (byte)'\t')))
        {
            throw new HttpException("The response has a malformed chunk size.");
        }

        return size;
    }

    private static int HexValue(byte c) => c switch
    {
        >= (byte)'0' and <= (byte)'9' => c - '0',
        >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
        _ => -1,
    };

    /// <summary>The index of the next CRLF from <paramref name="start"/>, or -1.</summary>
    private static int IndexOfLineEnd(byte[] data, int start, int length)
    {
        for (int i = start; i + 1 < length; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n')
            {
                return i;
            }
        }

        return -1;
    }

    private static HttpException Truncated() => new("The server closed the connection in the middle of a chunked body.");
}
