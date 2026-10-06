import std/[net, asyncnet, asyncdispatch, nativesockets]
import types, common

proc buildRequest(proxy: Proxy, targetHost: string, targetPort: Port): string =
  result = newStringOfCap(32)
  result.add('\x04')
  result.add('\x01')
  let p = targetPort.toBytes
  result.add(p[0].char)
  result.add(p[1].char)

  if isIpv4(targetHost):
    let ip = parseIpAddress(targetHost)
    for b in ip.address_v4:
      result.add(b.char)
    result.add(proxy.username)
    result.add('\x00')
  elif proxy.remoteDns or proxy.kind == pkSocks4a:
    # socks4a fake ip marker
    result.add("\x00\x00\x00\x01")
    result.add(proxy.username)
    result.add('\x00')
    result.add(targetHost)
    result.add('\x00')
  else:
    # resolve host for strict socks4
    let ent = getHostByName(targetHost)
    if ent.addrList.len == 0:
      raise newException(ProxyConnectError, "cannot resolve host " & targetHost)
    let ip = parseIpAddress(ent.addrList[0])
    for b in ip.address_v4:
      result.add(b.char)
    result.add(proxy.username)
    result.add('\x00')

proc verifyResponse(resp: string) =
  if resp.len != 8:
    raise newException(ProxyConnectError, "invalid socks4 response length")
  let status = resp[1].byte
  if status == 0x5A:
    return
  case status
  of 0x5B: raise newException(ProxyConnectError, "socks4 request rejected")
  of 0x5C: raise newException(ProxyConnectError, "socks4 identd failed")
  of 0x5D: raise newException(ProxyConnectError, "socks4 userid error")
  else: raise newException(ProxyConnectError, "socks4 failed with code " & $status)

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  let req = buildRequest(proxy, targetHost, targetPort)
  sock.send(req)
  let resp = recvExact(sock, 8, timeout)
  verifyResponse(resp)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] {.async.} =
  let req = buildRequest(proxy, targetHost, targetPort)
  await sock.send(req)
  let resp = await recvExact(sock, 8)
  verifyResponse(resp)
