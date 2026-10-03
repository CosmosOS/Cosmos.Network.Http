<h1 align="center">CosmosHTTP Client 🚀</h1>
<p>
  <a href="https://www.nuget.org/packages/Cosmos.Network.Http/" target="_blank">
    <img alt="Version" src="https://img.shields.io/nuget/v/Cosmos.Network.Http.svg" />
  </a>
  <a href="https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt" target="_blank">
    <img alt="License: BSD Clause 3 License" src="https://img.shields.io/badge/license-BSD License-yellow.svg" />
  </a>
</p>

> CosmosHTTP is an HTTP/1.1 client, `https://` included, made in C# for the Cosmos operating system construction kit.

## Usage

Add the package to your kernel .csproj:

```xml
<ItemGroup>
    <PackageReference Include="Cosmos.Network.Http" Version="2.1.0" />
</ItemGroup>
```

The kernel needs networking (`CosmosEnableNetwork`, on by default), an IP configuration (DHCP or static) and, for host names, a DNS server. It also needs a Cosmos that plugs `RandomNumberGenerator` with a real random generator, whether it asks for `https://` or not: the TLS code is part of the package, and a kernel without that plug does not link (see [HTTPS](#https)). `Send()` runs the request on the calling thread and returns the response once it has arrived whole:

```csharp
using System;
using System.IO;
using Cosmos.Network.Http;

HttpResponse response = new HttpRequest("http://httpforever.com/").Send();

Console.WriteLine($"{response.StatusCode} {response.ReasonPhrase}, {response.Content.Length} bytes");
File.WriteAllBytes("/0/index.html", response.Content);
```

`Send()` returns error statuses too; `EnsureSuccessStatusCode()` turns them into an `HttpException`, and `GetString()` decodes the body with the charset of its Content-Type:

```csharp
string json = new HttpRequest("https://example.com/data.json").Send().EnsureSuccessStatusCode().GetString();
```

A request can set its method, body, headers, timeout and how many redirects it follows:

```csharp
HttpResponse response = new HttpRequest("http://example.com/api")
{
    Method = "POST",
    Body = Encoding.UTF8.GetBytes("{\"name\":\"cosmos\"}"),
    Headers = { ["Content-Type"] = "application/json" },
    Timeout = 10_000,  // how long the server may stay silent, in milliseconds (15 s by default)
    MaxRedirects = 0,  // return redirects instead of following them (5 by default)
    // Optional: one line per response and redirect.
    Log = message => Cosmos.Kernel.System.Diagnostics.Log.WriteString(message + "\n"),
}.Send();
```

The Host header comes from the URL. Setting it in `Headers` reaches a virtual host by IP address:

```csharp
new HttpRequest("http://34.223.124.45/") { Headers = { ["Host"] = "neverssl.com" } }.Send();
```

### HTTPS

`https://` URLs run TLS 1.3 or 1.2 through [BouncyCastle](https://github.com/bcgit/bc-csharp), all managed code: the BCL's `SslStream` and cryptography call OpenSSL, which a kernel does not have. The client offers ECDHE key exchange (X25519, P-256, P-384) with AES-GCM, ChaCha20-Poly1305 and, for old TLS 1.2 servers, AES-CBC, and asks for `http/1.1` through ALPN.

A request goes on only with a server whose certificate chain leads to one of Mozilla's roots (embedded in the package, from [curl's extract](https://curl.se/docs/caextract.html) of 2026-09-25), every certificate on it valid now, signed with SHA-2 or EdDSA and allowed to issue what it issued, and whose certificate names the host. Otherwise `Send()` throws an `HttpException` that tells why:

```
The certificate of expired.badssl.com is not trusted: the certificate expired on 2015-04-12 23:59:59 UTC.
```

`ServerCertificateValidation` decides instead, given what the server presented and what the built-in check made of it (`Error` is `null` when it trusts the server). To trust one self-signed server too, compare its `Fingerprint`, the SHA-256 of its certificate in uppercase hex (`openssl x509 -noout -fingerprint -sha256 -in cert.pem | tr -d :`):

```csharp
new HttpRequest("https://10.0.2.2:8443/")
{
    ServerCertificateValidation = certificate => certificate.Error is null
        || certificate.Fingerprint == "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
}.Send();
```

Redirects from `https://` to `http://` are not followed, and a redirect to another server no longer sends the `Authorization`, `Proxy-Authorization`, `Cookie` and `Host` headers set by hand.

On a Cosmos kernel:

- TLS keys come from `RandomNumberGenerator`, which a kernel without a plug for it cannot even link: use a Cosmos that has one.
- Certificate dates are checked against `DateTime.UtcNow`: the kernel's clock has to be right, which it is in QEMU, whose RTC holds UTC.
- The first handshake also loads the roots and warms BouncyCastle up, so it takes longer than the next ones.

### Limits

- No revocation check (OCSP or CRLs), no client certificates, no session resumption, and no fetching of an intermediate certificate a server leaves out.
- A response with neither Content-Length nor chunked encoding ends when the server closes the connection, close_notify or not, as many servers skip it: over `https://`, someone in the middle could cut such a response short unnoticed.
- Host names are matched as given: internationalized names have to be written in their `xn--` form.
- Each request opens a connection of its own, and the server closes it once it has answered.
- Responses come without content coding (`Accept-Encoding: identity`): a Cosmos kernel has no gzip to undo.
- The whole body is held in memory.

### Threads

`Send()` never waits in `Thread.Sleep`: it waits in `Socket.Poll`, which returns at once on a Cosmos kernel. So it runs on the kernel's main loop, which must never block, as well as on a thread of its own. TLS runs on the same thread: BouncyCastle is driven without blocking, handed what the socket received and asked for what to send.

## Authors

👤 **[@valentinbreiz](https://github.com/valentinbreiz)**

👤 **[@2881099](https://github.com/2881099)** (the first version was inspired by [TcpClientHttpRequest](https://github.com/2881099/TcpClientHttpRequest))

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

Feel free to check [issues page](https://github.com/CosmosOS/Cosmos.Network.Http/issues).

## 📝 License

Copyright © 2023-2026 [CosmosOS](https://github.com/CosmosOS).

This project is [BSD Clause 3](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt) licensed. It depends on [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) (MIT), and embeds Mozilla's root certificates, [`resources/cacert.pem`](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/resources/cacert.pem), under the [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/) (see [THIRD-PARTY-NOTICES.txt](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/THIRD-PARTY-NOTICES.txt)). To refresh them, replace that file with the latest `https://curl.se/ca/cacert.pem`.
