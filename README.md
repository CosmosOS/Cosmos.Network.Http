<h1 align="center">CosmosHTTP Client 🚀</h1>
<p>
  <a href="https://www.nuget.org/packages/Cosmos.Network.Http/" target="_blank">
    <img alt="Version" src="https://img.shields.io/nuget/v/Cosmos.Network.Http.svg" />
  </a>
  <a href="https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt" target="_blank">
    <img alt="License: BSD Clause 3 License" src="https://img.shields.io/badge/license-BSD License-yellow.svg" />
  </a>
</p>

> CosmosHTTP is an HTTP/1.1 client made in C# for the Cosmos operating system construction kit.

## Usage

Add the package to your kernel .csproj:

```xml
<ItemGroup>
    <PackageReference Include="Cosmos.Network.Http" Version="2.0.0" />
</ItemGroup>
```

The kernel needs networking (`CosmosEnableNetwork`, on by default), an IP configuration (DHCP or static) and, for host names, a DNS server. `Send()` runs the request on the calling thread and returns the response once it has arrived whole:

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
string json = new HttpRequest("http://example.com/data.json").Send().EnsureSuccessStatusCode().GetString();
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

### Limits

- `http://` only: there is no TLS, so `https://` URLs, and redirects to them, throw.
- Each request opens a connection of its own, and the server closes it once it has answered.
- Responses come without content coding (`Accept-Encoding: identity`): a Cosmos kernel has no gzip to undo.
- The whole body is held in memory.

### Threads

`Send()` never waits in `Thread.Sleep`: it waits in `Socket.Poll`, which returns at once on a Cosmos kernel. So it runs on the kernel's main loop, which must never block, as well as on a thread of its own.

## Authors

👤 **[@valentinbreiz](https://github.com/valentinbreiz)**

👤 **[@2881099](https://github.com/2881099)** (the first version was inspired by [TcpClientHttpRequest](https://github.com/2881099/TcpClientHttpRequest))

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

Feel free to check [issues page](https://github.com/CosmosOS/Cosmos.Network.Http/issues).

## 📝 License

Copyright © 2023-2026 [CosmosOS](https://github.com/CosmosOS).

This project is [BSD Clause 3](https://github.com/CosmosOS/Cosmos.Network.Http/blob/main/LICENSE.txt) licensed.
