# prx  
### universal proxy client and server library for Nim  
![Nim](https://img.shields.io/badge/Nim-2.0%2B-555?style=flat&logo=nim&logoColor=ffe953&labelColor=12131a)
[![License](https://img.shields.io/github/license/thebadinteger/prx)](LICENSE)
[![CI](https://github.com/thebadinteger/prx/actions/workflows/ci.yml/badge.svg)](https://github.com/thebadinteger/prx/actions/workflows/ci.yml)

---

- [Features](#features)
- [Start](#start)
- [Examples](#examples)
- [API](#api)
- [Protocols](#protocols)
- [Authentication](#authentication)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [License](#license)

## Features:  
- Pure Nim & Zero Dependencies (std library only)
- Protocol support: `SOCKS4, SOCKS4a, SOCKS5, HTTP CONNECT, HTTP Forward, HTTPS`
- Full TCP and UDP support
- Multi-protocol unified combo server
- Remote DNS (`rdns`) toggle to prevent DNS leaks

## Start  
Install the library:  
```bash
nimble install prx
```  
Or add it directly to your project:
```bash
git clone https://github.com/thebadinteger/prx
```

### Standard `std/httpclient` drop-in:
```nim
import std/httpclient except Proxy
import prx

let p = proxy("socks5://user:password@1.2.3.4:1080")

# scoped execution with automatic adapter lifecycle cleanup
withProxy(p, proc(client: HttpClient) =
  echo client.getContent("https://httpbin.org/ip")
)

# or standalone client with explicit adapter lifecycle
let adapter = startAdapter(p)
let client = newHttpClient(adapter)
try:
  echo client.getContent("https://httpbin.org/user-agent")
finally:
  client.close()
  adapter.stop()
```  

### Raw socket TCP dial (Sync / Async):
```nim
import prx

let p = proxy("socks5://1.2.3.4:1080")

# synchronous socket
let sock = dial(p, "example.com", Port(80))
sock.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
echo sock.recvLine()
sock.close()

# asynchronous socket
proc main() {.async.} =
  let asyncSock = await dialAsync(p, "example.com", Port(80))
  await asyncSock.send("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
  echo await asyncSock.recvLine()
  asyncSock.close()

waitFor main()
```

### Start multi-protocol proxy server:
```nim
import prx

# unified server on port 8080 supporting socks5, socks4, and http simultaneously
let srv = server(Port(8080), bindAddr = "0.0.0.0", kind = skAuto)
srv.setAuth("user", "password")
srv.setLogger(proc(msg: string) = echo "[prx] ", msg)

echo "proxy server running on port 8080"
waitFor srv.start()
```

## Examples
Practical and runnable code examples are available in the [`examples/`](examples) directory:  
- [examples/httpclient](examples/httpclient/main.nim) - Standard `std/httpclient` integration via `newHttpClient` and `withProxy`
- [examples/server](examples/server/main.nim) - Unified combo server handling SOCKS5, SOCKS4, and HTTP on a single port
- [examples/checker](examples/checker/main.nim) - Concurrent dial checker measuring proxy latency over raw sockets
- [examples/chain](examples/chain/main.nim) - Tunneling traffic through a multi-hop proxy chain
- [examples/udp](examples/udp/main.nim) - SOCKS5 UDP Associate sending and receiving raw datagrams (DNS queries)
- [examples/bridge](examples/bridge/main.nim) - Local port forwarder / bridge for applications without proxy support
- [examples/rawsocket](examples/rawsocket/main.nim) - Direct raw socket connection and custom protocol stream

**Run any example:**
```bash
nim r -p:. examples/httpclient/main.nim
```  

## API
### Primary Functions
#### `prx.proxy` / `prx.parseProxy`
```nim
proc proxy*(raw: string, defaultKind = pkSocks5, timeout = 10000, remoteDns = true): Proxy
proc parseProxy*(raw: string, defaultKind = pkSocks5, timeout = 10000, defaultRemoteDns = true): Proxy
```
Parses URI strings (`socks5://...`, `socks5h://...`, `socks4://...`, `http://...`, `https://...`) or `host:port`, `user:pass@host:port`, and `host:port:user:pass` notations  
Supports query flags `?rdns=0` and `?rdns=1`

#### `prx.dial` / `prx.dialAsync`
```nim
proc dial*(proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1): Socket
proc dialAsync*(proxy: Proxy, targetHost: string, targetPort: Port): Future[AsyncSocket]
proc dial*(proxies: openArray[Proxy], targetHost: string, targetPort: Port, timeout = -1): Socket
proc dialAsync*(proxies: openArray[Proxy], targetHost: string, targetPort: Port): Future[AsyncSocket]
```
Establishes a connection to the target host and port through a single proxy or a multi-hop chain of proxies

#### `prx.dialUdp`
```nim
proc dialUdp*(proxy: Proxy): Future[UdpRelay]
proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string): Future[void]
proc recvFrom*(relay: UdpRelay, maxSize = 65535): Future[tuple[host: string, port: Port, data: string]]
```
Establishes an RFC 1928 SOCKS5 UDP Associate relay for bi-directional raw UDP packet forwarding

#### `prx.newHttpClient` / `prx.withProxy`
```nim
proc startAdapter*(upstream: Proxy, bindAddr = "127.0.0.1"): LocalAdapter
proc newHttpClient*(adapter: LocalAdapter): HttpClient
proc newAsyncHttpClient*(adapter: LocalAdapter): AsyncHttpClient
proc withProxy*(proxy: Proxy, action: proc(client: HttpClient))
proc withProxyAsync*(proxy: Proxy, action: proc(client: AsyncHttpClient): Future[void])
```
Drop-in wrapper enabling standard `std/httpclient` to route requests through any SOCKS4, SOCKS4a, SOCKS5, or HTTPS proxy  
Caller owns the adapter and must call `adapter.stop()` after `client.close()`

#### `prx.server` / `prx.newServer`
```nim
proc server*(port: Port = Port(1080), bindAddr = "127.0.0.1", kind = skAuto, upstream: Proxy = nil): ProxyServer
proc start*(server: ProxyServer): Future[void]
proc stop*(server: ProxyServer)
proc setAuth*(server: ProxyServer, username, password: string)
proc setFilter*(server: ProxyServer, handler: FilterHandler)
proc setLogger*(server: ProxyServer, handler: LogHandler)
```
Configures and launches a multi-protocol proxy server (`skAuto`, `skSocks5`, `skSocks4`, `skHttp`). Can optionally forward upstream to another proxy

#### `prx.pipe` / `prx.startBridge`
```nim
proc pipe*(sockA, sockB: AsyncSocket): Future[tuple[bytesAtoB, bytesBtoA: int64]]
proc startBridge*(localPort: Port, proxy: Proxy, targetHost: string, targetPort: Port, bindAddr = "127.0.0.1"): Future[void]
```
Bidirectional socket streaming pump and local TCP bridge forwarder

## Protocols

| Protocol | Scheme | RFC / Spec | Auth | IPv4 | IPv6 | Domain (Remote DNS) | UDP Associate |
|---|---|---|---|---|---|---|---|
| **SOCKS5** | `socks5://`, `socks5h://` | [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928) | User/Pass | Yes | Yes | Yes (`ATYP 0x03`) | Yes |
| **SOCKS4a** | `socks4a://` | SOCKS4a Spec | UserID | Yes | No | Yes (Domain ext) | No |
| **SOCKS4** | `socks4://` | SOCKS4 Spec | UserID | Yes | No | Local DNS | No |
| **HTTP CONNECT** | `http://` | [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231) | Basic | Yes | Yes | Yes | No |
| **HTTPS (TLS)** | `https://` | [RFC 2818](https://datatracker.ietf.org/doc/html/rfc2818) | Basic | Yes | Yes | Yes | No |

## Authentication
1. **SOCKS5 Username/Password (RFC 1929)**: Standard subnegotiation (`0x01` version, 1-byte length prefixes)
2. **HTTP Basic Authentication (RFC 7617)**: `Proxy-Authorization: Basic <base64>` header
3. **SOCKS4 UserID**: Null-terminated username payload

Credentials can be supplied directly in URL (`socks5://user:pass@host:port`) or via parameters (`newProxy(host, port, username = "user", password = "pwd")`).

## Specifications
| Name | Area |
|---|---|
| [RFC 1928, SOCKS Protocol Version 5](https://datatracker.ietf.org/doc/html/rfc1928) | socks5 handshake, connect & udp associate |
| [RFC 1929, SOCKS5 Username/Password Authentication](https://datatracker.ietf.org/doc/html/rfc1929) | socks5 authentication subnegotiation |
| [SOCKS 4 & 4A Protocol Specification](https://www.openssh.com/txt/socks4.protocol) | socks4 connect & socks4a domain extension |
| [RFC 7231 / RFC 9110, HTTP/1.1 CONNECT](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6) | http connect tunneling |
| [RFC 7617, HTTP Basic Authentication](https://datatracker.ietf.org/doc/html/rfc7617) | basic proxy authorization |

## Architecture  
```
prx/
- prx.nim
- prx.nimble
- prx/
-- types.nim    # Proxy, ProxyKind, exceptions, URL parser
-- common.nim   # Socket helpers, IP validation, datagram reader
-- socks4.nim   # SOCKS4 and SOCKS4a client handshakes
-- socks5.nim   # SOCKS5 client handshake, auth, IPv4/IPv6/Domain
-- http.nim     # HTTP CONNECT tunnel client
-- dialer.nim   # Universal dial, dialAsync, TLS wrapping, proxy chaining
-- tunnel.nim   # Duplex pipe, startBridge
-- server.nim   # Multi-protocol server (skAuto, skSocks5, skSocks4, skHttp)
-- udp.nim      # RFC 1928 SOCKS5 UDP Associate, encode/decode, udp bridge
-- adapter.nim  # std/httpclient drop-in adapter and LocalAdapter bridge
- examples/     # Practical runnable examples
- tests/        # Modular test suite
```

## Documentation
Full API technical reference is available in **[`API.md`](API.md)**

## License  
Made by [badinteger](https://github.com/thebadinteger) `[MIT License]`
