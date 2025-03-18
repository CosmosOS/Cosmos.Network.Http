/*
* PROJECT:          CosmosHttp Development
* CONTENT:          Http Request class
* PROGRAMMERS:      Valentin Charbonnier <valentinbreiz@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CosmosHttp.Client
{
    public class HttpRequest : HttpPacket
    {
        private const int DEFAULT_TIMEOUT = 20000;
        private const string DEFAULT_USER_AGENT = "CosmosHttp Client (CosmosOS)";
        
        private TcpClient _client;
        private string _remote;
        private string _path;
        private int _timeout = DEFAULT_TIMEOUT;
        private NetworkStream _stream;
        private HttpResponse _response;

        public string Path
        {
            get => _path;
            set => _path = value;
        }

        public HttpResponse Response => _response;

        public int Timeout
        {
            get => _timeout;
            set => _timeout = value;
        }

        public HttpRequest()
        {
            _headers.Add("Connection", "Keep-Alive");
            _headers.Add("Accept", "*/*");
            _headers.Add("User-Agent", DEFAULT_USER_AGENT);
            _headers.Add("Accept-Language", "en-us");
            _headers.Add("Accept-Encoding", "gzip, deflate");
        }

        public void Close()
        {
            if (_client != null)
            {
                _stream?.Close();
                _client.Close();
                _client = null;
            }
        }

        public void Send()
        {
            Send(string.Empty);
        }

        public virtual void Send(string data)
        {
            Send(data, 0);
        }

        private void Send(string data, int redirections)
        {
            _data = data;

            _headers.Remove("Content-Length");
            if (!string.IsNullOrEmpty(data) && string.Compare(_method, "post", true) == 0)
            {
                _headers["Content-Length"] = Encoding.ASCII.GetBytes(data).Length.ToString();
                if (string.IsNullOrEmpty(_headers["Content-Type"]))
                {
                    _headers["Content-Type"] = $"application/x-www-form-urlencoded; charset={_charset}";
                }
                else if (_headers["Content-Type"].IndexOf("multipart/form-data") == -1)
                {
                    if (_headers["Content-Type"].IndexOf("application/x-www-form-urlencoded") == -1)
                    {
                        _headers["Content-Type"] += "; application/x-www-form-urlencoded";
                    }
                    if (_headers["Content-Type"].IndexOf("charset=") == -1)
                    {
                        _headers["Content-Type"] += $"; charset={_charset}";
                    }
                }
                data += "\r\n\r\n";
            }
            _headers["Host"] = _domain;

            StringBuilder httpBuilder = new StringBuilder();
            httpBuilder.AppendFormat("{0} {1} HTTP/1.1\r\n", _method, _path);
            
            foreach (var header in _headers)
            {
                httpBuilder.AppendFormat("{0}: {1}\r\n", header.Key, header.Value);
            }

            httpBuilder.AppendFormat("\r\n{0}", data);
            _head = httpBuilder.ToString();
            byte[] request = Encoding.ASCII.GetBytes(_head);
            
            EstablishConnection();
            SendRequest(request);
            receive(_stream, redirections, _ip);
        }

        private void EstablishConnection()
        {
            if (_client == null || _remote == null)
            {
                _remote = _ip;
                Close();
                _client = new TcpClient(_ip, 80);
            }
        }

        private void SendRequest(byte[] request)
        {
            try
            {
                _stream = getStream();
                _stream.Write(request, 0, request.Length);
            }
            catch
            {
                Close();
                _client = new TcpClient(_ip, 80);
                _stream = getStream();
                _stream.Write(request, 0, request.Length);
            }
        }

        protected void receive(Stream stream, int redirections, string action)
        {
            _response = null;
            byte[] bytes = new byte[1024];
            int bytesRead = 0;
            byte[] headBuffer = null;
            byte[] bodyBuffer = null;
            Exception exception = null;

            while (true)
            {
                try
                {
                    bytesRead = stream.Read(bytes, 0, bytes.Length);
                    if (bytesRead == 0)
                    {
                        if (headBuffer == null || headBuffer.Length == 0)
                        {
                            throw new Exception("headBuffer is empty and no more data to read");
                        }
                        break;
                    }
                }
                catch (Exception e)
                {
                    exception = e;
                    break;
                }

                if (_response == null)
                {
                    headBuffer = AppendToBuffer(headBuffer, bytes, bytesRead);
                    int headerDelimiterIndex = Utils.findBytes(headBuffer, new byte[] { 13, 10, 13, 10 }, 0);
                    
                    if (headerDelimiterIndex != -1)
                    {
                        CreateResponseFromHeader(headBuffer, headerDelimiterIndex);
                        
                        int bodyLength = headBuffer.Length - headerDelimiterIndex - 4;
                        bodyBuffer = new byte[bodyLength];
                        Array.Copy(headBuffer, headerDelimiterIndex + 4, bodyBuffer, 0, bodyLength);
                    }
                }
                else
                {
                    _response.Received += bytesRead;
                    bodyBuffer = AppendToBuffer(bodyBuffer, bytes, bytesRead);
                }

                if (_response != null && _response.ContentLength >= 0 && _response.ContentLength <= bodyBuffer.Length)
                {
                    break;
                }
            }

            HandleResponseCompletion(bodyBuffer, exception);
        }

        private byte[] AppendToBuffer(byte[] existingBuffer, byte[] newData, int bytesRead)
        {
            int oldLength = existingBuffer != null ? existingBuffer.Length : 0;
            byte[] newBuffer = new byte[oldLength + bytesRead];
            
            if (existingBuffer != null)
            {
                Array.Copy(existingBuffer, 0, newBuffer, 0, oldLength);
            }
            
            Array.Copy(newData, 0, newBuffer, oldLength, bytesRead);
            return newBuffer;
        }

        private void CreateResponseFromHeader(byte[] headBuffer, int headerDelimiterIndex)
        {
            byte[] header = new byte[headerDelimiterIndex];
            Array.Copy(headBuffer, 0, header, 0, headerDelimiterIndex);
            _response = new HttpResponse(this, header);
            _response.Received += headBuffer.Length - headerDelimiterIndex - 4;
        }

        private void HandleResponseCompletion(byte[] bodyBuffer, Exception exception)
        {
            if (_response == null)
            {
                this.closeTcp();
                ThrowWebException(exception);
            }
            else
            {
                _response.SetStream(bodyBuffer);
                this.closeTcp();
            }
        }

        private void ThrowWebException(Exception exception)
        {
            List<string> requestHeaders = new List<string>();
            requestHeaders.Add($"{_method.ToUpper()} {_ip} HTTP/1.1");
            
            foreach (var header in _headers)
            {
                requestHeaders.Add($"{header.Key}: {header.Value}");
            }

            string requestHeadersStr = string.Join("\r\n", requestHeaders.ToArray());
            
            if (exception == null)
            {
                throw new WebException($"WebException {requestHeadersStr}");
            }
            else
            {
                throw new WebException($"{exception.Message}\r\n{requestHeadersStr}", exception);
            }
        }

        protected bool closeTcp()
        {
            this.Close();
            return false;
        }

        protected NetworkStream getStream()
        {
            return _client.GetStream();
        }
    }

    public class Utils
    {
        public static int findBytes(byte[] source, byte[] find, int startIndex)
        {
            if (find == null || find.Length == 0 || source == null || source.Length == 0)
                return -1;
                
            if (startIndex < 0) 
                startIndex = 0;
                
            int idx = -1, idx2 = startIndex - 1;
            
            do
            {
                idx2 = idx = Array.FindIndex<byte>(source, Math.Min(idx2 + 1, source.Length), b => b == find[0]);
                
                if (idx2 != -1)
                {
                    for (int a = 1; a < find.Length; a++)
                    {
                        if (++idx2 >= source.Length || source[idx2] != find[a])
                        {
                            idx = -1;
                            break;
                        }
                    }
                    if (idx != -1) break;
                }
            } while (idx2 != -1);
            
            return idx;
        }
    }
} 
