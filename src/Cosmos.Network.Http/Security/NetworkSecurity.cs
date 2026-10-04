//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

// nanoFramework's System.Net NetworkSecurity.cs. Cosmos: SslProtocols is .NET's
// (System.Security.Authentication.SslProtocols, the same values), and SslNative, nanoFramework's native TLS
// (mbedTLS), is managed code over BouncyCastle in SslNative.cs.

namespace Cosmos.Network.Http
{
    /// <summary>
    /// The verification scheme to use for authentication.
    /// </summary>
    public enum SslVerification
    {
        /// <summary>
        /// No verification of certificates is required for authentication.
        /// </summary>
        NoVerification = 1,
        /// <summary>
        /// If authenticating as a client, verifies the peer certificate and fails if no certificate is sent. If authenticating as a server, 
        /// it verifies the peer certificate only if a certificate is sent.
        /// </summary>
        VerifyPeer = 2,
        /// <summary>
        /// A certificate is required for authentication. If authenticating as a client, the server certificate is required. 
        /// If authenticating as a server, the client certificate is required.
        /// </summary>
        CertificateRequired = 4,
        /// <summary>
        /// Verify the client certificate only once. Applies only to authenticating as a server.
        /// </summary>
        VerifyClientOnce = 8,
    }
}
