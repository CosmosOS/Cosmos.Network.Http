//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using System.Diagnostics;

namespace Cosmos.Network.Http.Headers
{
    /// <summary>
    /// Key/value pairs of headers. The value is either a raw <see cref="string"/> or a <see cref="HttpHeaders.HeaderStoreItemInfo"/>.
    /// </summary>
    internal struct HeaderEntry
    {
        public HeaderDescriptor Key;
        public object Value;

        public HeaderEntry(
            HeaderDescriptor key,
            object value)
        {
            Key = key;
            Value = value;
        }
    }

    /// <summary>
    /// A collection of headers and their values as defined in RFC 2616.
    /// </summary>
    public abstract class HttpHeaders
    {
        internal WebHeaderCollection _headerStore = new WebHeaderCollection(true);

        private readonly HttpHeaderType _allowedHeaderTypes;
        private readonly HttpHeaderType _treatAsCustomHeaderTypes;

        /// <summary>
        /// Initializes a new instance of the HttpHeaders class.
        /// </summary>
        protected HttpHeaders()
          : this(
                HttpHeaderType.All,
                HttpHeaderType.None)
        {
        }

        internal HttpHeaders(
            HttpHeaderType allowedHeaderTypes,
            HttpHeaderType treatAsCustomHeaderTypes)
        {
            // Should be no overlap
            Debug.Assert((allowedHeaderTypes & treatAsCustomHeaderTypes) == 0);

            _allowedHeaderTypes = allowedHeaderTypes & ~HttpHeaderType.NonTrailing;
            _treatAsCustomHeaderTypes = treatAsCustomHeaderTypes & ~HttpHeaderType.NonTrailing;
        }


        /// <summary>
        /// Adds the specified header and its value into the <see cref="HttpHeaders"/> collection.
        /// </summary>
        /// <param name="name">The header to add to the collection.</param>
        /// <param name="value">The content of the header.</param>
        /// <exception cref="ArgumentNullException">The values cannot be <see langword="null"/> or empty.</exception>
        public void Add(
            string name,
            string value)
        {
            // Cosmos: the headers HttpWebRequest restricts but .NET's HttpClient takes (Accept, User-Agent, Referer,
            // Range, If-Modified-Since), which nanoFramework refused here too: a request had no way to name its user
            // agent. Those the request sets itself (Host, Connection, Content-Length, Transfer-Encoding, Expect) stay
            // refused.
            if (IsCallerHeader(name))
            {
                _headerStore.AddWithoutValidate(name, value);
                return;
            }

            _headerStore.Add(name, value);
        }

        /// <summary>
        /// Returns whether a specific header exists in the <see cref="HttpHeaders"/> collection.
        /// </summary>
        /// <param name="name">The specific header.</param>
        /// <returns><see langword="true"/> if the specified header exists in the collection; otherwise <see langword="false"/>.</returns>
        /// <remarks>Cosmos: .NET's, which nanoFramework lacks: the headers of a response could be added, not read.</remarks>
        public bool Contains(string name)
        {
            return _headerStore.GetValues(name) != null;
        }

        /// <summary>
        /// Returns all header values for a specified header stored in the <see cref="HttpHeaders"/> collection.
        /// </summary>
        /// <param name="name">The specified header to return values for.</param>
        /// <returns>An array of header strings.</returns>
        /// <exception cref="InvalidOperationException">The header cannot be found.</exception>
        /// <remarks>Cosmos: .NET's, which nanoFramework lacks.</remarks>
        public IEnumerable<string> GetValues(string name)
        {
            if (!TryGetValues(name, out IEnumerable<string> values))
            {
                throw new InvalidOperationException("The header " + name + " is not there.");
            }

            return values;
        }

        /// <summary>
        /// Returns whether a specified header and specified values are stored in the <see cref="HttpHeaders"/> collection.
        /// </summary>
        /// <param name="name">The specified header.</param>
        /// <param name="values">The specified header values.</param>
        /// <returns><see langword="true"/> if the specified header name and values are stored in the collection; otherwise <see langword="false"/>.</returns>
        /// <remarks>Cosmos: .NET's, which nanoFramework lacks.</remarks>
        public bool TryGetValues(string name, out IEnumerable<string> values)
        {
            string[] found = _headerStore.GetValues(name);
            values = found;
            return found != null;
        }

        /// <summary>
        /// Removes the specified header from the <see cref="HttpHeaders"/> collection.
        /// </summary>
        /// <param name="name">The name of the header to remove from the collection.</param>
        /// <returns><see langword="true"/> if the header was removed; otherwise <see langword="false"/>.</returns>
        /// <remarks>Cosmos: .NET's, which nanoFramework lacks.</remarks>
        public bool Remove(string name)
        {
            if (!Contains(name))
            {
                return false;
            }

            _headerStore.RemoveInternal(name);
            return true;
        }

        private static bool IsCallerHeader(string name)
        {
            return name != null
                && (string.Equals(name, HttpKnownHeaderNames.Accept, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, HttpKnownHeaderNames.UserAgent, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, HttpKnownHeaderNames.Referer, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, HttpKnownHeaderNames.Range, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, HttpKnownHeaderNames.IfModifiedSince, StringComparison.OrdinalIgnoreCase));
        }

        internal virtual void AddHeaders(HttpHeaders sourceHeaders)
        {
            foreach (var headerKey in sourceHeaders._headerStore.AllKeys)
            {
                _headerStore.AddInternal(headerKey, sourceHeaders._headerStore[headerKey]);
            }
        }
    }
}
