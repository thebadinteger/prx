import std/[net, strutils, uri]
import hostport

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
  remoteDns = kind != pkSocks4
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

proc invalidProxy(reason, raw: string) {.noinline, noreturn.} =
  raise newException(ProxyProtocolError, reason & " in proxy string " & raw)

proc remoteDnsFor(kind: ProxyKind, fallback: bool): bool =
  case kind
  of pkSocks4: false
  of pkSocks4a: true
  else: fallback

proc parseProxyUri(raw, clean: string, timeout: int, defaultRemoteDns: bool): Proxy =
  let u = parseUri(clean)
  let kind = parseProxyKind(u.scheme)
  if u.hostname.len == 0:
    invalidProxy("missing host", raw)
  var port = case kind
    of pkSocks4, pkSocks4a, pkSocks5: Port(1080)
    of pkHttps: Port(443)
    of pkHttp: Port(8080)
  if u.port.len > 0 and not parsePort(u.port, port):
    invalidProxy("invalid port", raw)
  var rdns = u.scheme.toLowerAscii == "socks5h" or remoteDnsFor(kind, defaultRemoteDns)
  for key, value in decodeQuery(u.query):
    if key.toLowerAscii in ["rdns", "remotedns"]:
      case value.toLowerAscii
      of "0", "false": rdns = false
      of "1", "true": rdns = true
      else: discard
  newProxy(
    host = u.hostname,
    port = port,
    kind = kind,
    username = decodeUrl(u.username, decodePlus = false),
    password = decodeUrl(u.password, decodePlus = false),
    timeout = timeout,
    remoteDns = rdns
  )

proc parseProxy*(raw: string, defaultKind = pkSocks5, timeout = 10000, defaultRemoteDns = true): Proxy =
  let clean = raw.strip()
  if clean.len == 0:
    raise newException(ProxyProtocolError, "empty proxy string")

  if "://" in clean:
    return parseProxyUri(raw, clean, timeout, defaultRemoteDns)

  var host, username, password = ""
  var port: Port
  let at = clean.rfind('@')
  if at >= 0 and parseEndpoint(clean[at + 1 .. ^1], host, port):
    # user pass at host port
    let creds = clean[0 ..< at].split(':', 1)
    username = creds[0]
    if creds.len > 1:
      password = creds[1]
  else:
    # host port or host port user pass
    var rest = ""
    if not splitHost(clean, host, rest):
      invalidProxy("invalid format", raw)
    let fields = rest.split(':', 2)
    if not parsePort(fields[0], port):
      invalidProxy("missing or invalid port", raw)
    if fields.len == 3:
      username = fields[1]
      password = fields[2]
    elif fields.len != 1:
      invalidProxy("invalid format", raw)

  newProxy(
    host = host,
    port = port,
    kind = defaultKind,
    username = username,
    password = password,
    timeout = timeout,
    remoteDns = remoteDnsFor(defaultKind, defaultRemoteDns)
  )

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
    auth = encodeUrl(p.username, usePlus = false) & ":" &
      encodeUrl(p.password, usePlus = false) & "@"
  scheme & "://" & auth & joinHostPort(p.host, p.port)
