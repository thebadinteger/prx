# prx 
### API Reference

---

- [prx/types](#prxtypes)
- [prx/dialer](#prxdialer)
- [prx/udp](#prxudp)
- [prx/server](#prxserver)
- [prx/adapter](#prxadapter)
- [prx/tunnel](#prxtunnel)
- [prx/common](#prxcommon)
- [Error Handling](#error-handling)

---

## prx/types

Defines core data structures, proxy protocol types, URL parsers, and exception types

### `ProxyKind`
Supported proxy protocols:
```nim
type
  ProxyKind* = enum
    pkSocks4    # SOCKS4 (IPv4 only, local DNS)
    pkSocks4a   # SOCKS4a (domain extension, remote DNS)
    pkSocks5    # SOCKS5 (RFC 1928, IPv4, IPv6, Domain, UDP)
    pkHttp      # HTTP CONNECT tunneling or plain HTTP forward
    pkHttps     # HTTPS tunneling with TLS wrapping
```

### `Proxy`
Primary proxy configuration object:
```nim
type
  Proxy* = ref object
    kind*: ProxyKind        # Protocol type
    host*: string           # Proxy server host or IP
    port*: Port             # Proxy server port
    username*: string       # Authentication username
    password*: string       # Authentication password
    timeout*: int           # Connection timeout in milliseconds (default 10000)
    remoteDns*: bool        # Toggle remote DNS resolution (default true)
```

### `newProxy`
Constructs a new `Proxy` instance:
```nim
proc newProxy*(
  host: string,
  port: Port,
  kind = pkSocks5,
  username = "",
  password = "",
  timeout = 10000,
  remoteDns = true
): Proxy
```

### `parseProxy`
Parses proxy definition from URI or standard string formats:
```nim
proc parseProxy*(
  raw: string,
  defaultKind = pkSocks5,
  timeout = 10000,
  defaultRemoteDns = true
): Proxy
```
**Supported Formats:**
- `socks5://user:pass@1.2.3.4:1080`
- `socks5h://1.2.3.4:1080` (forces `remoteDns = true`)
- `socks4://1.2.3.4:1080` (`remoteDns = false` by default)
- `socks4a://1.2.3.4:1080` (`remoteDns = true` by default)
- `http://1.2.3.4:8080` / `https://1.2.3.4:8443`
- `1.2.3.4:1080` (uses `defaultKind`)
- `1.2.3.4:1080:user:pass`
- `user:pass@1.2.3.4:1080`
- Query parameters: `?rdns=0`, `?rdns=false`, `?remotedns=0` disable remote DNS resolution

---

## prx/dialer

Provides synchronous and asynchronous connection establishment, TLS wrapping, and multi-hop proxy chaining

### Single Proxy Dial
```nim
proc dial*(proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1): Socket
proc dialAsync*(proxy: Proxy, targetHost: string, targetPort: Port): Future[AsyncSocket]
```
Establishes a connection to `targetHost:targetPort` via `proxy`. Sockets are created with `buffered = false` for low latency

### Proxy Chaining
```nim
proc dial*(proxies: openArray[Proxy], targetHost: string, targetPort: Port, timeout = -1): Socket
proc dialAsync*(proxies: openArray[Proxy], targetHost: string, targetPort: Port): Future[AsyncSocket]
```
Tunnels through multiple proxies in sequence across different protocols (e.g. `[HTTP, SOCKS5, SOCKS4] > Target`)

### TLS Dialing
```nim
proc dialTls*(proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1): Socket
proc dialTlsAsync*(proxy: Proxy, targetHost: string, targetPort: Port): Future[AsyncSocket]
```
Connects through `proxy` and establishes an end-to-end TLS session with `targetHost` (requires compilation with `-d:ssl`)

---

## prx/udp

Implements RFC 1928 SOCKS5 UDP Associate for client-side datagram relaying and packet encoding.

### `UdpRelay`
```nim
type
  UdpRelay* = ref object
    controlSock*: AsyncSocket
    udpSock*: AsyncSocket
    relayHost*: string
    relayPort*: Port
    proxy*: Proxy
```

### `dialUdp`
```nim
proc dialUdp*(proxy: Proxy): Future[UdpRelay]
```
Negotiates authentication and SOCKS5 UDP Associate command with `proxy` over a TCP control socket, initializes a local UDP socket, and returns an active `UdpRelay`

### `sendTo`
```nim
proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string): Future[void]
proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string, remoteDns: bool): Future[void]
```
Encapsulates `data` into an RFC 1928 SOCKS5 UDP request packet and transmits it to the proxy's relay port

### `recvFrom`
```nim
proc recvFrom*(relay: UdpRelay, maxSize = 65535): Future[tuple[host: string, port: Port, data: string]]
```
Receives an encapsulated UDP response packet from the proxy and decodes source address, port, and payload

### `startUdpBridge`
```nim
proc startUdpBridge*(
  localPort: Port,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  bindAddr = "127.0.0.1"
): Future[void]
```
Listens for raw UDP datagrams on `localPort` and transparently forwards them to `targetHost:targetPort` through the SOCKS5 proxy

---

## prx/server

High-performance multi-protocol proxy server supporting SOCKS4, SOCKS4a, SOCKS5 (with auth and UDP Associate), and HTTP CONNECT / Plain HTTP

### `ServerKind`
```nim
type
  ServerKind* = enum
    skAuto      # Combo port: automatically detects SOCKS5, SOCKS4, or HTTP
    skSocks5    # Strict SOCKS5 server
    skSocks4    # Strict SOCKS4 server
    skHttp      # Strict HTTP proxy server
```

### `ProxyServer`
```nim
type
  ProxyServer* = ref object
    kind*: ServerKind
    bindAddr*: string
    port*: Port
    upstream*: Proxy
    running*: bool
    activeConnections*: int
    totalConnections*: int
    totalBytesSent*: int64
    totalBytesRecv*: int64
```

### Procedures
```nim
proc newServer*(port: Port = Port(1080), bindAddr = "127.0.0.1", kind = skAuto, upstream: Proxy = nil): ProxyServer
proc server*(port: Port = Port(1080), bindAddr = "127.0.0.1", kind = skAuto, upstream: Proxy = nil): ProxyServer
proc start*(server: ProxyServer): Future[void]
proc stop*(server: ProxyServer)
proc setAuth*(server: ProxyServer, username, password: string)
proc setAuth*(server: ProxyServer, handler: proc(u, p: string): bool {.closure, gcsafe.})
proc setFilter*(server: ProxyServer, handler: proc(host: string, port: Port): bool {.closure, gcsafe.})
proc setLogger*(server: ProxyServer, handler: proc(msg: string) {.closure, gcsafe.})
```

---

## prx/adapter

Drop-in adapters and bridges allowing `std/httpclient` or any third-party library to route traffic through any proxy

### `LocalAdapter`
```nim
type
  LocalAdapter* = ref object
    port*: Port
    bindAddr*: string
    upstream*: Proxy
    isThreaded*: bool
```

### Starting Adapters
```nim
proc startAdapter*(upstream: Proxy, bindAddr = "127.0.0.1"): LocalAdapter
proc startAdapterAsync*(upstream: Proxy, bindAddr = "127.0.0.1"): Future[LocalAdapter]
proc stop*(a: LocalAdapter)
```
Starts a lightweight local combo server. For synchronous code, `startAdapter` runs in an isolated background thread using shared memory

### Helper Properties
```nim
proc httpUrl*(a: LocalAdapter): string     # "http://127.0.0.1:port"
proc socks5Url*(a: LocalAdapter): string   # "socks5://127.0.0.1:port"
proc proxy*(a: LocalAdapter): Proxy        # Returns Proxy configured as pkHttp
proc socksProxy*(a: LocalAdapter): Proxy   # Returns Proxy configured as pkSocks5
```

### `std/httpclient` Drop-in Functions
```nim
proc newHttpClient*(adapter: LocalAdapter): HttpClient
proc newAsyncHttpClient*(adapter: LocalAdapter): AsyncHttpClient
proc withProxy*(proxy: Proxy, action: proc(client: HttpClient))
proc withProxyAsync*(proxy: Proxy, action: proc(client: AsyncHttpClient): Future[void])
```
Caller starts the adapter explicitly and owns its lifecycle. Close the client first, then stop the adapter. `withProxy` handles this automatically in scoped mode

---

## prx/tunnel

Bidirectional duplex socket piping and port bridges

```nim
proc pipe*(sockA, sockB: AsyncSocket): Future[tuple[bytesAtoB, bytesBtoA: int64]]
proc startBridge*(localPort: Port, proxy: Proxy, targetHost: string, targetPort: Port, bindAddr = "127.0.0.1"): Future[void]
```

---

## prx/common

Socket and address utilities

```nim
proc recvExact*(sock: Socket, size: int, timeout = -1): string
proc recvExact*(sock: AsyncSocket, size: int): Future[string]
proc isIpv4*(host: string): bool
proc isIpv6*(host: string): bool
proc recvDatagram*(sock: AsyncSocket, maxSize = 65535): Future[tuple[data: string, address: string, port: Port]]
```

---

## Error Handling

Hierarchy of proxy exceptions:
```nim
ProxyError (CatchableError)
- ProxyAuthError       # Authentication credentials rejected or unsupported
- ProxyConnectError    # Target unreachable, connection refused, or tunnel failed
- ProxyTimeoutError    # Operation timed out
- ProxyProtocolError   # Invalid packet format, malformed handshake, or missing TLS
```
All errors inherit from `ProxyError` (and `CatchableError`), allowing global catching:
```nim
try:
  let sock = dial(p, "target.com", Port(80))
except ProxyAuthError:
  echo "bad credentials"
except ProxyError as e:
  echo "proxy failure: ", e.msg
```
