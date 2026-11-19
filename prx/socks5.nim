import std/[net, asyncnet, asyncdispatch]
import types, wire

const
  cmdConnect = '\x01'
  cmdUdpAssociate = '\x03'
  methodNone = '\x00'
  methodUserPass = '\x02'
  methodRejected = '\xFF'

proc hasAuth(proxy: Proxy): bool =
  proxy.username.len > 0

proc buildGreeting(proxy: Proxy): string =
  if proxy.hasAuth:
    "\x05\x02\x00\x02"
  else:
    "\x05\x01\x00"

proc buildAuth(proxy: Proxy): string =
  if proxy.username.len > 255 or proxy.password.len > 255:
    raise newException(ProxyAuthError, "socks5 username and password are limited to 255 bytes")
  result = newStringOfCap(3 + proxy.username.len + proxy.password.len)
  result.add('\x01')
  result.add(proxy.username.len.char)
  result.add(proxy.username)
  result.add(proxy.password.len.char)
  result.add(proxy.password)

proc buildRequest(proxy: Proxy, cmd: char, targetHost: string, targetPort: Port): string =
  result = newStringOfCap(32)
  result.add('\x05')
  result.add(cmd)
  result.add('\x00')
  result.addAddress(targetHost, targetPort, proxy.remoteDns)

proc needsAuth(methodReply: string, proxy: Proxy): bool =
  if methodReply[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 version in method reply")
  case methodReply[1]
  of methodNone:
    result = false
  of methodUserPass:
    if not proxy.hasAuth:
      raise newException(ProxyAuthError, "socks5 proxy requires username and password")
    result = true
  of methodRejected:
    raise newException(ProxyAuthError, "no acceptable auth methods")
  else:
    raise newException(ProxyAuthError, "unsupported auth method " & $methodReply[1].byte)

proc verifyAuth(authReply: string) =
  if authReply[0] != '\x01':
    raise newException(ProxyProtocolError, "invalid socks5 auth reply version")
  if authReply[1] != '\x00':
    raise newException(ProxyAuthError, "socks5 authentication failed")

proc repToMessage(rep: byte): string =
  case rep
  of 0x01: "general socks server failure"
  of 0x02: "connection not allowed by ruleset"
  of 0x03: "network unreachable"
  of 0x04: "host unreachable"
  of 0x05: "connection refused"
  of 0x06: "ttl expired"
  of 0x07: "command not supported"
  of 0x08: "address type not supported"
  else: "socks5 error " & $rep

proc verifyReply(header: string) =
  if header[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 reply header")
  let rep = header[1].byte
  if rep != 0x00:
    raise newException(ProxyConnectError, repToMessage(rep))

proc request(
  sock: Socket | AsyncSocket,
  proxy: Proxy,
  cmd: char,
  targetHost: string,
  targetPort: Port,
  timeout: int
): Future[HostPort] {.multisync.} =
  ## runs the whole negotiation and returns the address bound by the proxy
  let auth = if proxy.hasAuth: buildAuth(proxy) else: ""
  let req = buildRequest(proxy, cmd, targetHost, targetPort)

  await sock.send(buildGreeting(proxy))
  if needsAuth(await recvN(sock, 2, timeout), proxy):
    await sock.send(auth)
    verifyAuth(await recvN(sock, 2, timeout))

  await sock.send(req)
  let header = await recvN(sock, 4, timeout)
  verifyReply(header)
  result = await recvAddress(sock, header[3], timeout)

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  discard request(sock, proxy, cmdConnect, targetHost, targetPort, timeout)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] {.async.} =
  discard await request(sock, proxy, cmdConnect, targetHost, targetPort, -1)

proc udpAssociate*(sock: AsyncSocket, proxy: Proxy): Future[tuple[host: string, port: Port]] =
  ## negotiates a udp relay over the control connection sock and returns the relay address
  request(sock, proxy, cmdUdpAssociate, "0.0.0.0", Port(0), -1)
