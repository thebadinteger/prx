import std/[net, asyncnet, asyncdispatch]
import types, socks4, socks5, http

proc performHandshake(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout: int) =
  case proxy.kind
  of pkSocks4, pkSocks4a:
    socks4.handshake(sock, proxy, targetHost, targetPort, timeout)
  of pkSocks5:
    socks5.handshake(sock, proxy, targetHost, targetPort, timeout)
  of pkHttp, pkHttps:
    http.handshake(sock, proxy, targetHost, targetPort, timeout)

proc performHandshake(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] {.async.} =
  case proxy.kind
  of pkSocks4, pkSocks4a:
    await socks4.handshake(sock, proxy, targetHost, targetPort)
  of pkSocks5:
    await socks5.handshake(sock, proxy, targetHost, targetPort)
  of pkHttp, pkHttps:
    await http.handshake(sock, proxy, targetHost, targetPort)

proc dial*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1
): Socket =
  let t = if timeout >= 0: timeout else: proxy.timeout
  let sock = newSocket(buffered = false)
  try:
    sock.connect(proxy.host, proxy.port, timeout = t)
  except CatchableError as e:
    sock.close()
    raise newException(ProxyConnectError, "cannot connect to " & proxy.host & ":" & $proxy.port.int & " " & e.msg)

  try:
    if proxy.kind == pkHttps:
      when defined(ssl):
        var ctx = newContext()
        ctx.wrapConnectedSocket(sock, handshakeAsClient, proxy.host)
      else:
        raise newException(ProxyProtocolError, "https proxy requires -d:ssl")

    performHandshake(sock, proxy, targetHost, targetPort, t)
    return sock
  except CatchableError:
    sock.close()
    raise

proc dialAsync*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port
): Future[AsyncSocket] {.async.} =
  let sock = await asyncnet.dial(proxy.host, proxy.port, buffered = false)
  try:
    if proxy.kind == pkHttps:
      when defined(ssl):
        var ctx = newContext()
        ctx.wrapConnectedSocket(sock, handshakeAsClient, proxy.host)
      else:
        raise newException(ProxyProtocolError, "https proxy requires -d:ssl")

    await performHandshake(sock, proxy, targetHost, targetPort)
    return sock
  except CatchableError:
    sock.close()
    raise

proc dial*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port,
  timeout = -1
): Socket =
  if proxies.len == 0:
    raise newException(ProxyConnectError, "proxy chain cannot be empty")
  if proxies.len == 1:
    return dial(proxies[0], targetHost, targetPort, timeout)

  let first = proxies[0]
  let t = if timeout >= 0: timeout else: first.timeout
  let sock = newSocket(buffered = false)
  try:
    sock.connect(first.host, first.port, timeout = t)
  except CatchableError as e:
    sock.close()
    raise newException(ProxyConnectError, "cannot connect to " & first.host & ":" & $first.port.int & " " & e.msg)

  try:
    for i in 0 ..< proxies.len - 1:
      let current = proxies[i]
      let nextProxy = proxies[i + 1]
      performHandshake(sock, current, nextProxy.host, nextProxy.port, t)
      if nextProxy.kind == pkHttps:
        when defined(ssl):
          var ctx = newContext()
          ctx.wrapConnectedSocket(sock, handshakeAsClient, nextProxy.host)
        else:
          raise newException(ProxyProtocolError, "https proxy requires -d:ssl")

    let last = proxies[^1]
    performHandshake(sock, last, targetHost, targetPort, t)
    return sock
  except CatchableError:
    sock.close()
    raise

proc dialAsync*(
  proxies: seq[Proxy],
  targetHost: string,
  targetPort: Port
): Future[AsyncSocket] {.async.} =
  if proxies.len == 0:
    raise newException(ProxyConnectError, "proxy chain cannot be empty")
  if proxies.len == 1:
    return await dialAsync(proxies[0], targetHost, targetPort)

  let first = proxies[0]
  let sock = await asyncnet.dial(first.host, first.port, buffered = false)

  try:
    for i in 0 ..< proxies.len - 1:
      let current = proxies[i]
      let nextProxy = proxies[i + 1]
      await performHandshake(sock, current, nextProxy.host, nextProxy.port)
      if nextProxy.kind == pkHttps:
        when defined(ssl):
          var ctx = newContext()
          ctx.wrapConnectedSocket(sock, handshakeAsClient, nextProxy.host)
        else:
          raise newException(ProxyProtocolError, "https proxy requires -d:ssl")

    let last = proxies[^1]
    await performHandshake(sock, last, targetHost, targetPort)
    return sock
  except CatchableError:
    sock.close()
    raise

proc dialAsync*(
  proxies: openArray[Proxy],
  targetHost: string,
  targetPort: Port
): Future[AsyncSocket] =
  dialAsync(@proxies, targetHost, targetPort)

proc dialTls*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout = -1
): Socket =
  when defined(ssl):
    let sock = dial(proxy, targetHost, targetPort, timeout)
    try:
      var ctx = newContext()
      ctx.wrapConnectedSocket(sock, handshakeAsClient, targetHost)
      return sock
    except CatchableError:
      sock.close()
      raise
  else:
    raise newException(ProxyProtocolError, "tls support requires compiling with -d:ssl")

proc dialTlsAsync*(
  proxy: Proxy,
  targetHost: string,
  targetPort: Port
): Future[AsyncSocket] {.async.} =
  when defined(ssl):
    let sock = await dialAsync(proxy, targetHost, targetPort)
    try:
      var ctx = newContext()
      ctx.wrapConnectedSocket(sock, handshakeAsClient, targetHost)
      return sock
    except CatchableError:
      sock.close()
      raise
  else:
    raise newException(ProxyProtocolError, "tls support requires compiling with -d:ssl")
