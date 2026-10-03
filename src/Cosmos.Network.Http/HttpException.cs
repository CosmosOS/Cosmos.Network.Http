// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;

namespace Cosmos.Network.Http;

/// <summary>
/// A request that did not get a usable response: the host could not be
/// resolved or reached, the TLS handshake failed or the server's certificate
/// is not trusted, the server went silent or sent something that is not
/// HTTP, a redirect led nowhere, or <see cref="HttpResponse.EnsureSuccessStatusCode"/>
/// found an error status.
/// </summary>
public sealed class HttpException : Exception
{
    /// <summary>The status of the response that failed, or 0 when there was no response.</summary>
    public int StatusCode { get; }

    /// <summary>Creates an exception, with the status of the response that failed if there was one.</summary>
    public HttpException(string message, int statusCode = 0) : base(message)
    {
        StatusCode = statusCode;
    }

    /// <summary>Creates an exception for a failure underneath HTTP, a socket error for instance.</summary>
    public HttpException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
