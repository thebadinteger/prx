import std/[net, asyncnet, asyncdispatch]
import types, hostport, wire, socks4, socks5, http

type
  Attempt = ref object
    sock: AsyncSocket
    expired: bool

when defined(ssl):
  import std/openssl

  var defaultContext {.threadvar.}: SslContext

  proc tlsContext(custom: SslContext): SslContext =
    if not custom.isNil:
      return custom
    if defaultContext.isNil:
      defaultContext = newContext()
    defaultContext

  when defined(nimDisableCertificateValidation):
    proc expectHost(ssl: SslPtr, host: string) =
      discard
  else:
    # mirrors how std/openssl binds symbols that are missing from old libraries
    when compileOption("dynlibOverride", "ssl") or defined(noOpenSSLHacks):
      proc SSL_set1_host(ssl: SslPtr, hostname: cstring): cint {.cdecl, dynlib: DLLSSLName, importc.}
    else:
      import std/dynlib

      type SetHostProc = proc(ssl: SslPtr, hostname: cstring): cint {.cdecl, gcsafe, raises: [].}

      proc SSL_set1_host(ssl: SslPtr, hostname: cstring): cint =
        var setHost {.global.}: SetHostProc
        if setHost.isNil:
          let lib = loadLibPattern(DLLSSLName)
          if not lib.isNil:
            setHost = cast[SetHostProc](lib.symAddr("SSL_set1_host"))
        if setHost.isNil: 0 else: setHost(ssl, hostname)

    proc expectHost(ssl: SslPtr, host: string) =
      ## Makes openssl match the certificate against host during the handshake
      if not isIpAddress(host) and SSL_set1_host(ssl, host.cstring) != 1:
        raiseSSLError("cannot verify the certificate host, openssl 1.1.0 or newer is required")

proc wrapTls(sock: Socket, host: string, sslContext: SslContext) =
  when defined(ssl):
    tlsContext(sslContext).wrapSocket(sock)
    if not isIpAddress(host):
      discard SSL_set_tlsext_host_name(sock.sslHandle, host)
    expectHost(sock.sslHandle, host)
    ErrClearError()
    socketError(sock, SSL_connect(sock.sslHandle))
  else:
    raise newException(ProxyProtocolError, "tls to " & host & " requires compiling with -d:ssl")

proc wrapTls(sock: AsyncSocket, host: string, sslContext: SslContext) =
  when defined(ssl):
    # the handshake itself runs on the first read or write
    tlsContext(sslContext).wrapConnectedSocket(sock, handshakeAsClient, host)
    expectHost(sock.sslHandle, host)
  else:
    raise newException(ProxyProtocolError, "tls to " & host & " requires compiling with -d:ssl")

proc checkChain(proxies: openArray[Proxy], tlsTarget = false) =
  if proxies.len == 0:
    raise newException(ProxyConnectError, "proxy chain cannot be empty")
  var tlsLayers = if tlsTarget: 1 else: 0
  for proxy in proxies:
    if proxy.isNil:
      raise newException(ProxyConnectError, "proxy chain contains a nil proxy")
    if proxy.kind == pkHttps:
      inc tlsLayers
  # std sockets carry a single tls session so tls inside tls cannot be layered
  if tlsLayers > 1:
    raise newException(ProxyProtocolError,
      "tls inside tls is not supported, use at most one https proxy and no tls target behind it")
  when not defined(ssl):
    if tlsLayers > 0:
      raise newException(ProxyProtocolError, "tls support requires compiling with -d:ssl")

proc effectiveTimeout(proxy: Proxy, timeout: int): int =
  let t = if timeout >= 0: timeout else: proxy.timeout
  if t > 0: t else: -1

proc toProxyError(e: ref CatchableError, context: string): ref ProxyError =
  if e of ProxyError:
    (ref ProxyError)(e)
  elif e of TimeoutError:
    newException(ProxyTimeoutError, context & ": " & e.msg, e)
  else:
    newException(ProxyConnectError, context & ": " & e.msg, e)

proc connectFailure(proxy: Proxy): string =
  "cannot connect to " & joinHostPort(proxy.host, proxy.port)

proc handshakeFailure(proxy: Proxy): string =
  "handshake via " & joinHostPort(proxy.host, proxy.port) & " failed"

when defined(windows):
  import std/[nativesockets, oserrors]
  from std/winlean import TFdSet, Timeval, FD_ZERO, FD_SET, select, WSAEWOULDBLOCK, WSAEINPROGRESS

  proc connectWithin(sock: Socket, ip: IpAddress, port: Port, domain: Domain, timeout: int) =
    let fd = sock.getFd
    let ai = getAddrInfo($ip, port, domain)
    fd.setBlocking(false)
    let started = connect(fd, ai.ai_addr, ai.ai_addrlen.SockLen)
    let startError = osLastError()
    freeAddrInfo(ai)
    if started != 0:
      if startError.int32 != WSAEWOULDBLOCK and startError.int32 != WSAEINPROGRESS:
        raiseOSError(startError)
      var writable, failed: TFdSet
      FD_ZERO(writable)
      FD_SET(fd, writable)
      FD_ZERO(failed)
      FD_SET(fd, failed)
      var tv = Timeval(tv_sec: int32(timeout div 1000), tv_usec: int32((timeout mod 1000) * 1000))
      let ready = select(0, nil, addr writable, addr failed, addr tv)
      if ready < 0:
        raiseOSError(osLastError())
      if ready == 0:
        raise newException(TimeoutError, "Call to 'connect' timed out.")
      let pending = getSockOptInt(fd, SOL_SOCKET, SO_ERROR)
      if pending != 0:
        raiseOSError(OSErrorCode(pending))
    fd.setBlocking(true)
else:
  proc connectWithin(sock: Socket, ip: IpAddress, port: Port, domain: Domain, timeout: int) =
    sock.connect($ip, port, timeout = timeout)

proc connectTcp(proxy: Proxy, timeout: int): Socket =
  let ip = resolveHost(stripBrackets(proxy.host))
  let domain = if ip.family == IpAddressFamily.IPv6: AF_INET6 else: AF_INET
  result = newSocket(domain, buffered = false)
  try:
    if timeout > 0:
      connectWithin(result, ip, proxy.port, domain, timeout)
    else:
      result.connect($ip, proxy.port)
  except CatchableError:
    closeQuietly(result)
    raise

proc performHandshake(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout: int) =
  case proxy.kind
  of pkSocks4, pkSocks4a:
    socks4.handshake(sock, proxy, targetHost, targetPort, timeout)
  of pkSocks5:
    socks5.handshake(sock, proxy, targetHost, targetPort, timeout)
  of pkHttp, pkHttps:
    http.handshake(sock, proxy, targetHost, targetPort, timeout)

proc performHandshake(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port, timeout: int): Future[void] {.async.} =
  case proxy.kind
  of pkSocks4, pkSocks4a:
    await socks4.handshake(sock, proxy, targetHost, targetPort)
  of pkSocks5:
    await socks5.handshake(sock, proxy, targetHost, targetPort)
  of pkHttp, pkHttps:
    await http.handshake(sock, proxy, targetHost, targetPort)

proc tunnelThrough(
  sock: Socket | AsyncSocket,
  proxies: seq[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout: int,
  sslContext: SslContext
): Future[void] {.multisync.} =
  if proxies[0].kind == pkHttps:
    wrapTls(sock, proxies[0].host, sslContext)
  for i in 0 .. proxies.high:
    if i < proxies.high:
      let next = proxies[i + 1]
      await performHandshake(sock, proxies[i], next.host, next.port, timeout)
      if next.kind == pkHttps:
        wrapTls(sock, next.host, sslContext)
    else:
      await performHandshake(sock, proxies[i], targetHost, targetPort, timeout)

proc dial*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Socket =
  checkChain(proxies)
  let first = proxies[0]
  let t = effectiveTimeout(first, timeout)
  var sock: Socket = nil
  var context = connectFailure(first)
  try:
    sock = connectTcp(first, t)
    context = handshakeFailure(first)
    tunnelThrough(sock, @proxies, targetHost, targetPort, t, sslContext)
    result = sock
  except CatchableError as e:
    if not sock.isNil:
      closeQuietly(sock)
    raise toProxyError(e, context)

proc dial*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Socket =
  dial([proxy], targetHost, targetPort, timeout, sslContext)

proc dialChain(
  attempt: Attempt,
  proxies: seq[Proxy],
  targetHost: string,
  targetPort: Port,
  sslContext: SslContext
): Future[AsyncSocket] {.async.} =
  let first = proxies[0]
  var context = connectFailure(first)
  try:
    attempt.sock = await asyncnet.dial(stripBrackets(first.host), first.port, buffered = false)
    if attempt.expired:
      raise newException(ProxyTimeoutError, context & ": timed out")
    context = handshakeFailure(first)
    await tunnelThrough(attempt.sock, proxies, targetHost, targetPort, -1, sslContext)
    result = attempt.sock
  except CatchableError as e:
    if not attempt.sock.isNil:
      closeQuietly(attempt.sock)
    raise toProxyError(e, context)

proc dialAsync*(
  proxies: seq[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] {.async.} =
  checkChain(proxies)
  let t = effectiveTimeout(proxies[0], timeout)
  let attempt = Attempt()
  let pending = dialChain(attempt, proxies, targetHost, targetPort, sslContext)
  if t > 0 and not await withTimeout(pending, t):
    # closing the socket makes the abandoned handshake fail instead of lingering
    attempt.expired = true
    if not attempt.sock.isNil:
      closeQuietly(attempt.sock)
    raise newException(ProxyTimeoutError,
      "dial via " & joinHostPort(proxies[0].host, proxies[0].port) & " timed out after " & $t & "ms")
  result = await pending

proc dialAsync*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] =
  dialAsync(@proxies, targetHost, targetPort, timeout, sslContext)

proc dialAsync*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] =
  dialAsync(@[proxy], targetHost, targetPort, timeout, sslContext)

proc dialTls*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Socket =
  checkChain(proxies, tlsTarget = true)
  let sock = dial(proxies, targetHost, targetPort, timeout)
  try:
    wrapTls(sock, targetHost, sslContext)
    result = sock
  except CatchableError as e:
    closeQuietly(sock)
    raise toProxyError(e, "tls handshake with " & targetHost & " failed")

proc dialTls*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Socket =
  dialTls([proxy], targetHost, targetPort, timeout, sslContext)

proc dialTlsAsync*(
  proxies: seq[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] {.async.} =
  checkChain(proxies, tlsTarget = true)
  let sock = await dialAsync(proxies, targetHost, targetPort, timeout)
  try:
    wrapTls(sock, targetHost, sslContext)
    result = sock
  except CatchableError as e:
    closeQuietly(sock)
    raise toProxyError(e, "tls handshake with " & targetHost & " failed")

proc dialTlsAsync*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] =
  dialTlsAsync(@proxies, targetHost, targetPort, timeout, sslContext)

proc dialTlsAsync*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1,
  sslContext: SslContext = nil
): Future[AsyncSocket] =
  dialTlsAsync(@[proxy], targetHost, targetPort, timeout, sslContext)
