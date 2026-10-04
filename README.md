<h1 align="center">CosmosHTTP 🚀</h1>
<p>
  <a href="https://www.nuget.org/packages/Cosmos.Network.Http/" target="_blank">
    <img alt="Version" src="https://img.shields.io/nuget/v/Cosmos.Network.Http.svg" />
  </a>
  <a href="https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt" target="_blank">
    <img alt="License: BSD Clause 3 License" src="https://img.shields.io/badge/license-BSD License-yellow.svg" />
  </a>
</p>

> CosmosHTTP is an HTTP/1.1 client and server, `https://` included, for the Cosmos operating system construction kit: [.NET nanoFramework's System.Net.Http](https://github.com/nanoframework/System.Net.Http) ported to Cosmos Gen3.

The sources keep nanoFramework's folder tree and file names (`nanoFramework.System.Net.Http` became `src/Cosmos.Network.Http`), in the `Cosmos.Network.Http` namespace, and its API: `HttpClient`, `HttpListener`, `HttpWebRequest`. What the port changed is marked `Cosmos:` in the code. The library uses the BCL's `System.Net.Sockets`, which a Cosmos kernel plugs onto its network stack, so it runs on a desktop as is, which is how the tests drive it.

## Usage

Add the package to your kernel .csproj:

```xml
<ItemGroup>
    <PackageReference Include="Cosmos.Network.Http" Version="3.0.0" />
</ItemGroup>
```

The kernel needs networking (`CosmosEnableNetwork`, on by default), an IP configuration (DHCP or static) and, for host names, a DNS server. Keep `ImplicitUsings` off, or remove `System.Net.Http` from them: its `HttpClient` would clash with this one. For the same reason, don't import `System.Net` next to `Cosmos.Network.Http`.

### Client

```csharp
using System;
using System.Text;
using Cosmos.Network.Http;

using HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

string text = client.GetString("http://example.com/");
byte[] data = client.GetByteArray("https://example.com/");

using HttpResponseMessage response = client.Post("http://10.0.2.2:8000/api", new StringContent("{\"name\":\"cosmos\"}", Encoding.UTF8, "application/json"));
Console.WriteLine((int)response.StatusCode + " " + response.Content.ReadAsString());
```

`GetString`, `GetByteArray` and `GetStream` throw an `HttpRequestException` for an error status; `Get`, `Post`, `Put`, `Patch`, `Delete` and `Send` return it. They read the whole body, and every failure (connection, DNS, TLS, a response cut short or malformed) is an `HttpRequestException` whose innermost exception says why. With `HttpCompletionOption.ResponseHeadersRead` the body is read from the content's stream later, whose failures are `IOException`s. Dispose the responses you get: their connection goes back to the pool or is closed then.

`DefaultRequestHeaders` (and a request's `Headers`) take `Accept`, `User-Agent`, `Referer`, `Range` and `If-Modified-Since`, but not the headers the request sets itself (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`). A response's headers are read with `TryGetValues`, `GetValues` and `Contains`, its body's type with `Content.Headers.ContentType` (null without one). Redirects are not followed: a 3xx comes back as the response, its `Location` in its headers.

`Timeout` is infinite by default, as on nanoFramework: set it, or a server that stops answering holds the thread for the 5 minutes each read may wait. It bounds each wait for the response's head and for its body.

`HttpClient` asks the server to close the connection after each response (`DefaultRequestHeaders.ConnectionClose`, as nanoFramework does). Set it to `false` to keep connections alive: the next request to the same server, with the same TLS settings, reuses one.

### Server

```csharp
using System.Text;
using Cosmos.Network.Http;

HttpListener listener = new HttpListener("http", 8080);
listener.Start();

while (listener.IsListening)
{
    HttpListenerContext context = listener.GetContext();
    if (context == null)
    {
        break; // stopped
    }

    HttpListenerResponse response = context.Response;
    byte[] body = Encoding.UTF8.GetBytes("hello from cosmos " + context.Request.RawUrl);
    response.ContentType = "text/plain";
    response.ContentLength64 = body.Length;
    response.OutputStream.Write(body, 0, body.Length);
    response.Close();
}
```

One thread serves every connection: `GetContext` accepts them, runs their TLS handshakes (without waiting on any client) and watches those waiting for a request, and returns the next request that has arrived. It sleeps 50 ms between rounds when nothing is pending, so call it from a thread of its own, never from the kernel's main loop, and handle each request on that thread. `Stop`, `Close` and `Abort` may come from another thread, which leaves the sockets to the serving one: waiting in `GetContext`, it returns `null` within a round; handling a request, it answers it, then closes them once the response is closed, or in its next `GetContext` call (which throws `InvalidOperationException`), or in its own `Close`.

A response closes its connection unless `KeepAlive` is set (`response.KeepAlive = context.Request.KeepAlive` keeps what the client asked for), and even then when it doesn't turn out whole (its `ContentLength64` not all written, or no length and no `SendChunked`), or when the handler left the request's body unread. `SendChunked` streams a body of unknown length.

### HTTPS

`https://` runs TLS 1.3 or 1.2 through [BouncyCastle](https://github.com/bcgit/bc-csharp), all managed code, in place of nanoFramework's native mbedTLS: the BCL's `SslStream` and cryptography call OpenSSL, which a kernel does not have. Key exchanges are ECDHE (X25519, P-256, P-384), ciphers AES-GCM and ChaCha20-Poly1305 (preferred on a CPU without AES-NI, as a Cosmos kernel runs), plus AES-CBC for old TLS 1.2 servers.

A client goes on only with a server whose certificate chain leads to a trusted certificate, each one valid now and allowed to issue what it issued, and whose certificate names the host. The trusted certificates are Mozilla's roots (embedded in the package, from [curl's extract](https://curl.se/docs/caextract.html)), or those given:

```csharp
// For this client: one CA, PEM or DER.
HttpClient client = new HttpClient { HttpsAuthentCert = new X509Certificate(caPem), SslProtocols = SslProtocols.None };

// For every client given none: replaces the embedded roots.
CertificateManager.AddCaCertificateBundle(bundlePem);
```

`SslProtocols` is TLS 1.2 by default, as on nanoFramework; `SslProtocols.None` offers TLS 1.3 and 1.2. `SslVerification.NoVerification` skips the check.

A server needs a certificate with its private key, PEM or DER (PKCS#8, encrypted or not, PKCS#1 RSA or SEC1 EC):

```csharp
HttpListener listener = new HttpListener("https", 443)
{
    HttpsCert = new X509Certificate2(certificatePem, privateKeyPem, null),
    SslProtocols = SslProtocols.None,
};
```

On a Cosmos kernel:

- TLS keys come from `RandomNumberGenerator`, which Cosmos plugs with a kernel generator.
- Certificate dates are checked against `DateTime.UtcNow`: the kernel's clock has to be right, which it is in QEMU, whose RTC holds UTC.
- The first handshake loads the roots and warms BouncyCastle up, so it takes longer than the next ones.

### Limits

- HTTP/1.1 only, IPv4 only, no proxy authentication, no content coding (a Cosmos kernel has no gzip to undo).
- No revocation check (OCSP or CRLs), no session resumption, no fetching of an intermediate certificate a server leaves out, no name constraints (a certificate with critical ones is refused, as mbedTLS refuses it).
- The server asks no client certificate and offers no ALPN. Certificates are read with RSA, EC (named curves), Ed25519 or Ed448 keys only.
- Cosmos's network stack takes no lock: a listener serving on one thread while requests run on another may run into each other. Keep the sockets to one thread at a time.

## Tests

`dotnet test` runs nanoFramework's unit tests (`HttpUnitTests`, on MSTest, but for those of its own `System.Uri`, which the port leaves out for .NET's) and the port's: TLS client and server over loopback, certificate checks and key formats, `HttpClient` against `HttpListener` over http and https.

## Authors

👤 **[@valentinbreiz](https://github.com/valentinbreiz)**

The HTTP code is .NET nanoFramework's, by the .NET Foundation and contributors.

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

Feel free to check [issues page](https://github.com/CosmosOS/Cosmos.Network.Http/issues).

## 📝 License

Copyright © 2023-2026 [CosmosOS](https://github.com/CosmosOS).

This project is [BSD Clause 3](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt) licensed. Its HTTP code is .NET nanoFramework's System.Net.Http and System.Net, under the MIT license. It depends on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) (MIT), and embeds Mozilla's root certificates, [`resources/cacert.pem`](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/resources/cacert.pem), under the [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/) (see [THIRD-PARTY-NOTICES.txt](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/THIRD-PARTY-NOTICES.txt)). To refresh them, replace that file with the latest `https://curl.se/ca/cacert.pem`.
