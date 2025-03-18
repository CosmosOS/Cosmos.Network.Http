/*
* PROJECT:          CosmosHttp Development
* CONTENT:          Http Response class
* PROGRAMMERS:      Valentin Charbonnier <valentinbreiz@gmail.com>
*/

using System;
using System.Net;
using System.Text;

namespace CosmosHttp.Client
{
    public class HttpResponse : HttpPacket
    {
        private int _received = 0;
        private HttpStatusCode _statusCode;
        private int _contentLength = -1;
        private string _contentType;
        private string _server;
        private string _content;
        private string _contentEncoding = string.Empty;
        private byte[] _stream = new byte[0];

        public int Received
        {
            get => _received;
            internal set => _received = value;
        }

        public string TransferEncoding
        {
            get => _headers.ContainsKey("Transfer-Encoding") ? _headers["Transfer-Encoding"] : null;
            set => _headers["Transfer-Encoding"] = value;
        }

        public int ContentLength => _contentLength;

        public HttpStatusCode StatusCode => _statusCode;

        public string ContentType => _contentType;

        public string Server => _server;
        
        public string Content
        {
            get
            {
                if (_content == null)
                {
                    _content = Encoding.ASCII.GetString(_stream);
                }
                return _content;
            }
        }

        public HttpResponse(HttpRequest request, byte[] headBytes)
        {
            _ip = request.IP;
            _method = request.Method;
            _charset = request.Charset;
            
            ParseResponseHeader(headBytes);
        }

        private void ParseResponseHeader(byte[] headBytes)
        {
            string head = Encoding.ASCII.GetString(headBytes).Trim();
            _head = head;
            
            ParseStatusLine(ref head);
            ParseHeaders(head);
        }

        private void ParseStatusLine(ref string head)
        {
            int idx = head.IndexOf(' ');
            if (idx != -1)
            {
                head = head.Substring(idx + 1);
                
                idx = head.IndexOf(' ');
                if (idx != -1)
                {
                    _statusCode = (HttpStatusCode)int.Parse(head.Remove(idx));
                    head = head.Substring(idx + 1);
                }
                
                idx = head.IndexOf("\r\n");
                if (idx != -1)
                {
                    head = head.Substring(idx + 2);
                }
            }
        }

        private void ParseHeaders(string headerText)
        {
            string[] headers = headerText.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            
            foreach (string header in headers)
            {
                string[] headerParts = header.Split(new char[] { ':' }, 2);
                if (headerParts.Length == 2)
                {
                    string name = headerParts[0].Trim();
                    string value = headerParts[1].Trim();
                    
                    ProcessHeader(name, value);
                }
            }
        }

        private void ProcessHeader(string name, string value)
        {
            switch (name.ToLower())
            {
                case "content-length":
                    if (!int.TryParse(value, out _contentLength))
                        _contentLength = -1;
                    break;
                    
                case "content-type":
                    _contentType = value;
                    ProcessContentTypeCharset(value);
                    break;
                    
                case "server":
                    _server = value;
                    break;
                    
                case "content-encoding":
                    _contentEncoding = value;
                    break;
                    
                default:
                    if (_headers.ContainsKey(name))
                    {
                        _headers[name] = value;
                    }
                    else
                    {
                        _headers.Add(name, value);
                    }
                    break;
            }
        }

        private void ProcessContentTypeCharset(string contentType)
        {
            int charsetIndex = contentType.IndexOf("charset=", StringComparison.OrdinalIgnoreCase);
            if (charsetIndex != -1)
            {
                string charset = contentType.Substring(charsetIndex + 8).Split(';')[0].Trim();
                if (string.Compare(_charset, charset, StringComparison.OrdinalIgnoreCase) != 0)
                {
                    try
                    {
                        Encoding testEncode = Encoding.GetEncoding(charset);
                        _charset = charset;
                    }
                    catch (Exception ex)
                    {
                        Cosmos.HAL.Global.debugger.Send("Ex: " + ex.ToString());
                    }
                }
            }
        }

        public void SetStream(byte[] bodyBytes)
        {
            _stream = bodyBytes ?? new byte[0];
            _contentLength = _stream.Length;
        }

        public byte[] GetStream()
        {
            switch (_contentEncoding.ToLower())
            {
                case "gzip":
                    return GZip.Decompress(_stream);
                case "deflate":
                    return Deflate.Decompress(_stream);
                default:
                    return _stream;
            }
        }
    }
}
