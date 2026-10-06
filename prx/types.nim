import std/[net, strutils, uri]

type
  ProxyKind* = enum
    pkSocks4
    pkSocks4a
    pkSocks5
    pkHttp
    pkHttps

  Proxy* = ref object
    kind*: ProxyKind
    host*: string
    port*: Port
    username*: string
    password*: string
    timeout*: int
    remoteDns*: bool

  PrxProxy* = Proxy

  ProxyError* = object of CatchableError
  ProxyAuthError* = object of ProxyError
  ProxyConnectError* = object of ProxyError
  ProxyTimeoutError* = object of ProxyError
  ProxyProtocolError* = object of ProxyError

proc newProxy*(
  host: string,
  port: Port,
  kind = pkSocks5,
  username = "",
  password = "",
  timeout = 10000,
  remoteDns = true
): Proxy =
  Proxy(
    kind: kind,
    host: host,
    port: port,
    username: username,
    password: password,
    timeout: timeout,
    remoteDns: remoteDns
  )

proc toPort*(hi, lo: byte): Port =
  Port((hi.int shl 8) or lo.int)

proc toBytes*(p: Port): array[2, byte] =
  let val = p.uint16
  [byte(val shr 8), byte(val and 0xFF)]

proc parseProxyKind*(scheme: string): ProxyKind =
  case scheme.toLowerAscii
  of "socks4": pkSocks4
  of "socks4a": pkSocks4a
  of "socks5", "socks5h", "socks": pkSocks5
  of "http": pkHttp
  of "https": pkHttps
  else:
    raise newException(ProxyProtocolError, "unknown proxy protocol " & scheme)

proc parseProxy*(raw: string, defaultKind = pkSocks5, timeout = 10000, defaultRemoteDns = true): Proxy =
  let clean = raw.strip()
  if clean.len == 0:
    raise newException(ProxyProtocolError, "empty proxy string")

  # parse uri format
  if "://" in clean:
    let u = parseUri(clean)
    let kind = parseProxyKind(u.scheme)
    let portInt = if u.port.len > 0: parseInt(u.port)
                  elif kind in {pkSocks4, pkSocks4a, pkSocks5}: 1080
                  elif kind == pkHttps: 443
                  else: 8080
    var rdns = if kind == pkSocks4: false
               elif u.scheme.toLowerAscii == "socks5h" or kind == pkSocks4a: true
               else: defaultRemoteDns
    let q = u.query.toLowerAscii
    if "rdns=0" in q or "rdns=false" in q or "remotedns=0" in q or "remotedns=false" in q:
      rdns = false
    elif "rdns=1" in q or "rdns=true" in q or "remotedns=1" in q or "remotedns=true" in q:
      rdns = true
    return newProxy(
      host = u.hostname,
      port = Port(portInt),
      kind = kind,
      username = u.username,
      password = u.password,
      timeout = timeout,
      remoteDns = rdns
    )


  # parse user pass at host port
  if '@' in clean:
    let atParts = clean.split('@', 1)
    let credParts = atParts[0].split(':', 1)
    let hostParts = atParts[1].split(':', 1)
    if hostParts.len < 2:
      raise newException(ProxyProtocolError, "missing port in proxy string " & raw)
    let username = credParts[0]
    let password = if credParts.len > 1: credParts[1] else: ""
    let port = Port(parseInt(hostParts[1]))
    return newProxy(
      host = hostParts[0],
      port = port,
      kind = defaultKind,
      username = username,
      password = password,
      timeout = timeout
    )

  # parse host port or host port user pass
  let parts = clean.split(':')
  case parts.len
  of 2:
    return newProxy(
      host = parts[0],
      port = Port(parseInt(parts[1])),
      kind = defaultKind,
      timeout = timeout
    )
  of 4:
    return newProxy(
      host = parts[0],
      port = Port(parseInt(parts[1])),
      kind = defaultKind,
      username = parts[2],
      password = parts[3],
      timeout = timeout
    )
  else:
    raise newException(ProxyProtocolError, "invalid proxy format " & raw)

proc `$`*(p: Proxy): string =
  if p.isNil: return "nil"
  let scheme = case p.kind
    of pkSocks4: "socks4"
    of pkSocks4a: "socks4a"
    of pkSocks5: "socks5"
    of pkHttp: "http"
    of pkHttps: "https"
  var auth = ""
  if p.username.len > 0 or p.password.len > 0:
    auth = p.username & ":" & p.password & "@"
  scheme & "://" & auth & p.host & ":" & $p.port.int
