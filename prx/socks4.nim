import std/[net, asyncnet, asyncdispatch]
import types, hostport, wire

proc buildRequest(proxy: Proxy, targetHost: string, targetPort: Port): string =
  if '\x00' in proxy.username or proxy.username.len > 255:
    raise newException(ProxyAuthError, "socks4 userid must be at most 255 bytes without nul")
  let host = stripBrackets(targetHost)
  var ip: IpAddress
  let literal = tryParseIp(host, ip)
  let isV4 = literal and ip.family == IpAddressFamily.IPv4
  let useDomain = not isV4 and (proxy.remoteDns or proxy.kind == pkSocks4a)
  if useDomain:
    checkHost(host)
  elif literal and not isV4:
    raise newException(ProxyProtocolError, "socks4 does not support ipv6 target " & host)
  elif not literal:
    # resolve host for strict socks4
    ip = resolveHost(host, allowIpv6 = false)

  result = newStringOfCap(16 + proxy.username.len + host.len)
  result.add("\x04\x01")
  result.addPort(targetPort)
  if useDomain:
    # socks4a fake ip marker
    result.add("\x00\x00\x00\x01")
  else:
    for b in ip.address_v4:
      result.add(b.char)
  result.add(proxy.username)
  result.add('\x00')
  if useDomain:
    result.add(host)
    result.add('\x00')

proc verifyResponse(resp: string) =
  if resp.len != 8 or resp[0] != '\x00':
    raise newException(ProxyProtocolError, "invalid socks4 response")
  let status = resp[1].byte
  case status
  of 0x5A: discard
  of 0x5B: raise newException(ProxyConnectError, "socks4 request rejected")
  of 0x5C: raise newException(ProxyConnectError, "socks4 identd failed")
  of 0x5D: raise newException(ProxyConnectError, "socks4 userid error")
  else: raise newException(ProxyConnectError, "socks4 failed with code " & $status)

proc connectThrough(
  sock: Socket | AsyncSocket,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout: int
): Future[void] {.multisync.} =
  await sock.send(buildRequest(proxy, targetHost, targetPort))
  verifyResponse(await recvN(sock, 8, timeout))

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  connectThrough(sock, proxy, targetHost, targetPort, timeout)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] =
  connectThrough(sock, proxy, targetHost, targetPort, -1)
