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
    remoteDns*: bool        # Toggle remote DNS resolution (default true, false for pkSocks4)
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
  remoteDns = kind != pkSocks4
): Proxy
```
`remoteDns` decides who resolves a host name target: the proxy (`true`) or the local resolver (`false`). It defaults to `false` only for `pkSocks4`, which then sends plain SOCKS4 requests with an IPv4 address. Setting it to `true` on a `pkSocks4` proxy sends the SOCKS4a domain extension instead

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
- `1.2.3.4:1080:user:pass` (the password may contain `:`)
- `user:pass@1.2.3.4:1080`
- IPv6 hosts in brackets: `socks5://[::1]:1080`, `[::1]:1080`, `user:pass@[::1]:1080`
- Query parameters: `?rdns=0`, `?rdns=false`, `?remotedns=0` disable remote DNS resolution

URI credentials are percent-decoded (`socks5://user:p%40ss@host:1080` gives the password `p@ss`), and `$proxy` percent-encodes them so the result parses back to the same proxy  
Formats without a scheme use `defaultKind`  
`defaultRemoteDns` applies to `pkSocks5`, `pkHttp` and `pkHttps`; `pkSocks4` always starts with local DNS and `pkSocks4a` with remote DNS, in every format  
A missing host, a missing port in the scheme-less formats, or a port outside `1..65535` raises `ProxyProtocolError`

---

## prx/dialer

Provides synchronous and asynchronous connection establishment, TLS wrapping, and multi-hop proxy chaining

### Single Proxy Dial
```nim
proc dial*(proxy: Proxy, targetHost: string, targetPort: Port,
           timeout = -1, sslContext: SslContext = nil): Socket
proc dialAsync*(proxy: Proxy, targetHost: string, targetPort: Port,
                timeout = -1, sslContext: SslContext = nil): Future[AsyncSocket]
```
Establishes a connection to `targetHost:targetPort` via `proxy`. Sockets are created with `buffered = false` for low latency

`sslContext` is only used for the TLS session with a `pkHttps` proxy, see [TLS](#tls)

`targetHost` is an IPv4 address, an IPv6 address (with or without brackets) or a host name of at most 255 bytes; anything else raises `ProxyProtocolError` before a request is sent

### Timeouts
`timeout` is in milliseconds. A negative value (the default) uses `proxy.timeout` of the first proxy; an effective value of `0` or less disables the timeout
- `dialAsync` treats it as one deadline for the TCP connect and every handshake of the chain, including TLS with a `pkHttps` proxy. When it expires the socket is closed and `ProxyTimeoutError` is raised
- `dialTlsAsync` gives the TLS handshake with the target the same amount of time again
- `dial` applies it to the TCP connect and to each proxy handshake read separately. A TLS handshake on a sync socket is not timed

### Proxy Chaining
```nim
proc dial*(proxies: openArray[Proxy], targetHost: string, targetPort: Port,
           timeout = -1, sslContext: SslContext = nil): Socket
proc dialAsync*(proxies: openArray[Proxy], targetHost: string, targetPort: Port,
                timeout = -1, sslContext: SslContext = nil): Future[AsyncSocket]
```
Tunnels through multiple proxies in sequence across different protocols (e.g. `[HTTP, SOCKS5, SOCKS4] > Target`)

An empty chain or a `nil` entry raises `ProxyConnectError`. A chain may contain at most one `pkHttps` proxy, at any position, because a socket carries a single TLS session

### TLS Dialing
```nim
proc dialTls*(proxy: Proxy, targetHost: string, targetPort: Port,
              timeout = -1, sslContext: SslContext = nil): Socket
proc dialTlsAsync*(proxy: Proxy, targetHost: string, targetPort: Port,
                   timeout = -1, sslContext: SslContext = nil): Future[AsyncSocket]
proc dialTls*(proxies: openArray[Proxy], targetHost: string, targetPort: Port,
              timeout = -1, sslContext: SslContext = nil): Socket
proc dialTlsAsync*(proxies: openArray[Proxy], targetHost: string, targetPort: Port,
                   timeout = -1, sslContext: SslContext = nil): Future[AsyncSocket]
```
Connects through a proxy or a chain and establishes an end-to-end TLS session with `targetHost`

- Both complete the TLS handshake before returning, so a rejected certificate is a `ProxyConnectError` from the dial itself
- No proxy in the chain may be `pkHttps` (`ProxyProtocolError`), for the same single TLS session reason

### TLS
TLS to a `pkHttps` proxy and to a `dialTls` target requires compilation with `-d:ssl`; without it these calls raise `ProxyProtocolError` before connecting

- The certificate chain and its host name are verified for both sync and async sockets on every platform, with OpenSSL and with the LibreSSL that macOS ships (on Windows OpenSSL 1.0.2 or newer is required). IP address hosts get chain verification only. `-d:nimDisableCertificateValidation` turns verification off
- By default one `newContext()` per thread is shared by all dials. Pass `sslContext` for a private CA, client certificates or other settings; the host name check still applies while the context verifies peers
```nim
let ctx = newContext(caFile = "corporate-ca.pem")
let sock = dialTls(p, "internal.example", Port(443), sslContext = ctx)
```

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
proc dialUdp*(proxy: Proxy, timeout = -1): Future[UdpRelay]
proc close*(relay: UdpRelay)
```
Negotiates authentication and SOCKS5 UDP Associate command with `proxy` over a TCP control socket, initializes a local UDP socket, and returns an active `UdpRelay`

`timeout` works like in `dialAsync`. When the proxy reports an unspecified relay address (`0.0.0.0`), the address of the control connection is used. The association ends when the control connection closes, so keep the relay open and `close` it when done

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

Datagrams that do not come from the relay address and fragmented datagrams are skipped. A malformed packet from the relay raises `ProxyProtocolError`

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
    totalBytesSent*: int64      # client to target
    totalBytesRecv*: int64      # target to client
    handshakeTimeout*: int      # ms a client may take to send its request (default 30000, 0 disables)
```

### Procedures
```nim
proc newServer*(port: Port = Port(1080), bindAddr = "127.0.0.1", kind = skAuto, upstream: Proxy = nil): ProxyServer
proc server*(port: Port = Port(1080), bindAddr = "127.0.0.1", kind = skAuto, upstream: Proxy = nil): ProxyServer
proc start*(server: ProxyServer): Future[void]
proc listen*(server: ProxyServer)
proc serve*(server: ProxyServer): Future[void]
proc stop*(server: ProxyServer)
proc setAuth*(server: ProxyServer, username, password: string)
proc setAuth*(server: ProxyServer, handler: proc(u, p: string): bool {.closure, gcsafe.})
proc setFilter*(server: ProxyServer, handler: proc(host: string, port: Port): bool {.closure, gcsafe.})
proc setLogger*(server: ProxyServer, handler: proc(msg: string) {.closure, gcsafe.})
```

`listen` binds the socket and raises on failure; with `Port(0)` it stores the chosen port in `server.port`. `serve` accepts clients until `stop`. `start` runs both
```nim
let srv = server(Port(0))
srv.listen()
echo "listening on ", srv.port.int
waitFor srv.serve()
```

### Behavior
- **Relaying** is half-close aware: when one side finishes sending, the other side sees end of stream and can still reply. Both sockets are closed once both directions are done or either one fails
- **Plain HTTP requests** are forwarded with `Connection: close`, one request per client connection, without the `Proxy-*` headers. Malformed requests get `400`, oversized headers `431`
- **SOCKS5 replies** carry the local address of the outbound connection on success and distinguish refused (`0x05`) and unreachable-network (`0x03`) targets; other dial failures are host unreachable (`0x04`)
- **UDP Associate** binds the relay on the address the client connected to, accepts datagrams only from that client's IP and pins the first source port it uses. Malformed and fragmented datagrams are dropped. IPv4, IPv6 and host name destinations are relayed. The command is refused (`0x07`) when `upstream` is set, since datagrams would bypass the upstream proxy
- **SOCKS4** has no passwords: with `setAuth` the handler is called with the user id and an empty password
- **Limits**: request lines and headers up to 8192 bytes each, 128 headers, 255 bytes for SOCKS4 user ids and host names

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

Both raise when the local server cannot be bound (`startAdapter` as `ProxyConnectError`)

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
- ProxyProtocolError   # Invalid packet format, malformed handshake, invalid proxy string or target, or missing TLS
```
`dial`, `dialAsync`, `dialTls`, `dialTlsAsync` and `dialUdp` raise only `ProxyError` subtypes: socket and TLS failures are wrapped in `ProxyConnectError` and timeouts in `ProxyTimeoutError`, with the original exception kept as `parent`

All errors inherit from `ProxyError` (and `CatchableError`), allowing global catching:
```nim
try:
  let sock = dial(p, "target.com", Port(80))
except ProxyAuthError:
  echo "bad credentials"
except ProxyError as e:
  echo "proxy failure: ", e.msg
```
