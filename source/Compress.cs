using System;
using System.IO;
using System.Text;

namespace CosmosHttp
{
    public static class GZip
    {
        private const int BUFFER_SIZE = 4096;

        public static byte[] Decompress(Stream stream)
        {
            try
            {
                stream.Position = 0;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (Ionic.Zlib.GZipStream gzip = new Ionic.Zlib.GZipStream(stream, Ionic.Zlib.CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        while ((bytesRead = gzip.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            ms.Write(buffer, 0, bytesRead);
                        }
                    }
                    return ms.ToArray();
                }
            }
            catch 
            { 
                return stream is MemoryStream memStream ? memStream.ToArray() : new byte[0]; 
            }
        }

        public static byte[] Decompress(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];
                
            return Decompress(new MemoryStream(data));
        }

        public static byte[] Compress(string text)
        {
            if (string.IsNullOrEmpty(text))
                return new byte[0];
                
            return Compress(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] Compress(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];
                
            return Compress(data, 0, data.Length);
        }

        public static byte[] Compress(byte[] data, int startIndex, int length)
        {
            if (data == null || length <= 0 || startIndex < 0 || startIndex + length > data.Length)
                return new byte[0];
                
            using (MemoryStream ms = new MemoryStream())
            {
                using (Ionic.Zlib.GZipStream gzip = new Ionic.Zlib.GZipStream(ms, Ionic.Zlib.CompressionMode.Compress))
                {
                    gzip.Write(data, startIndex, length);
                }
                return ms.ToArray();
            }
        }
    }

    public static class Deflate
    {
        private const int BUFFER_SIZE = 4096;

        public static byte[] Decompress(Stream stream)
        {
            try
            {
                stream.Position = 0;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (Ionic.Zlib.DeflateStream deflate = new Ionic.Zlib.DeflateStream(stream, Ionic.Zlib.CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        while ((bytesRead = deflate.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            ms.Write(buffer, 0, bytesRead);
                        }
                    }
                    return ms.ToArray();
                }
            }
            catch 
            { 
                return stream is MemoryStream memStream ? memStream.ToArray() : new byte[0];
            }
        }

        public static byte[] Decompress(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];
                
            return Decompress(new MemoryStream(data));
        }

        public static byte[] Compress(string text)
        {
            if (string.IsNullOrEmpty(text))
                return new byte[0];
                
            return Compress(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] Compress(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];
                
            return Compress(data, 0, data.Length);
        }

        public static byte[] Compress(byte[] data, int startIndex, int length)
        {
            if (data == null || length <= 0 || startIndex < 0 || startIndex + length > data.Length)
                return new byte[0];
                
            using (MemoryStream ms = new MemoryStream())
            {
                using (Ionic.Zlib.DeflateStream deflate = new Ionic.Zlib.DeflateStream(ms, Ionic.Zlib.CompressionMode.Compress))
                {
                    deflate.Write(data, startIndex, length);
                }
                return ms.ToArray();
            }
        }
    }
}
