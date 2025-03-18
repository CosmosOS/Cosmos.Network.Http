/*
* PROJECT:          CosmosHttp Development
* CONTENT:          Base Http packet class
* PROGRAMMERS:      Valentin Charbonnier <valentinbreiz@gmail.com>
*/

using System;
using System.Collections.Generic;

namespace CosmosHttp
{
    public class HttpPacket : IDisposable
    {
        internal string _domain;
        internal string _ip;
        internal string _method = "GET";
        internal string _charset = "us-ascii";
        internal string _data;
        internal string _head;
        internal Dictionary<string, string> _headers;

        public HttpPacket()
        {
            _headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public string Method
        {
            get => _method;
            set => _method = value.ToUpper();
        }

        public string Domain
        {
            get => _domain;
            set => _domain = value;
        }

        public string IP
        {
            get => _ip;
            set => _ip = value;
        }

        public string Charset
        {
            get => _charset;
            set => _charset = value;
        }

        public Dictionary<string, string> Headers => _headers;

        public string GetHeader(string name)
        {
            return _headers.TryGetValue(name, out string value) ? value : null;
        }

        public void SetHeader(string name, string value)
        {
            _headers[name] = value;
        }

        public void RemoveHeader(string name)
        {
            if (_headers.ContainsKey(name))
            {
                _headers.Remove(name);
            }
        }

        public void Dispose()
        {
            _headers.Clear();
        }
    }
}
