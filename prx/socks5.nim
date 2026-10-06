import std/[net, asyncnet, asyncdispatch, nativesockets]
import types, common

proc buildGreeting(hasAuth: bool): string =
  if hasAuth:
    "\x05\x02\x00\x02"
  else:
    "\x05\x01\x00"

proc buildAuth(username, password: string): string =
  let ulen = min(username.len, 255)
  let plen = min(password.len, 255)
  result = newStringOfCap(3 + ulen + plen)
  result.add('\x01')
  result.add(ulen.char)
  if ulen > 0:
    result.add(username[0 ..< ulen])
  result.add(plen.char)
  if plen > 0:
    result.add(password[0 ..< plen])

proc buildConnect(proxy: Proxy, targetHost: string, targetPort: Port): string =
  result = newStringOfCap(32)
  result.add("\x05\x01\x00")
  if isIpv4(targetHost):
    result.add('\x01')
    let ip = parseIpAddress(targetHost)
    for b in ip.address_v4:
      result.add(b.char)
  elif isIpv6(targetHost):
    result.add('\x04')
    let ip = parseIpAddress(targetHost)
    for b in ip.address_v6:
      result.add(b.char)
  elif proxy.remoteDns:
    result.add('\x03')
    let dlen = min(targetHost.len, 255)
    result.add(dlen.char)
    result.add(targetHost[0 ..< dlen])
  else:
    # resolve host locally
    let ent = getHostByName(targetHost)
    if ent.addrList.len == 0:
      raise newException(ProxyConnectError, "cannot resolve host " & targetHost)
    let ip = parseIpAddress(ent.addrList[0])
    result.add('\x01')
    for b in ip.address_v4:
      result.add(b.char)
  let p = targetPort.toBytes
  result.add(p[0].char)
  result.add(p[1].char)


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

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  let hasAuth = proxy.username.len > 0
  sock.send(buildGreeting(hasAuth))

  let methodResp = recvExact(sock, 2, timeout)
  if methodResp[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 version in method reply")

  let selectedMethod = methodResp[1].byte
  if selectedMethod == 0xFF:
    raise newException(ProxyAuthError, "no acceptable auth methods")

  if selectedMethod == 0x02:
    sock.send(buildAuth(proxy.username, proxy.password))
    let authResp = recvExact(sock, 2, timeout)
    if authResp[1].byte != 0x00:
      raise newException(ProxyAuthError, "socks5 authentication failed")
  elif selectedMethod != 0x00:
    raise newException(ProxyAuthError, "unsupported auth method " & $selectedMethod)

  # send connect request
  sock.send(buildConnect(proxy, targetHost, targetPort))

  let header = recvExact(sock, 4, timeout)
  if header[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 reply header")
  let rep = header[1].byte
  if rep != 0x00:
    raise newException(ProxyConnectError, repToMessage(rep))

  # drain bound address
  let atyp = header[3].byte
  case atyp
  of 0x01:
    discard recvExact(sock, 4, timeout)
  of 0x03:
    let lenByte = recvExact(sock, 1, timeout)
    discard recvExact(sock, lenByte[0].int, timeout)
  of 0x04:
    discard recvExact(sock, 16, timeout)
  else:
    raise newException(ProxyProtocolError, "invalid address type " & $atyp)

  # drain bound port
  discard recvExact(sock, 2, timeout)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] {.async.} =
  let hasAuth = proxy.username.len > 0
  await sock.send(buildGreeting(hasAuth))

  let methodResp = await recvExact(sock, 2)
  if methodResp[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 version in method reply")

  let selectedMethod = methodResp[1].byte
  if selectedMethod == 0xFF:
    raise newException(ProxyAuthError, "no acceptable auth methods")

  if selectedMethod == 0x02:
    await sock.send(buildAuth(proxy.username, proxy.password))
    let authResp = await recvExact(sock, 2)
    if authResp[1].byte != 0x00:
      raise newException(ProxyAuthError, "socks5 authentication failed")
  elif selectedMethod != 0x00:
    raise newException(ProxyAuthError, "unsupported auth method " & $selectedMethod)

  # send connect request
  await sock.send(buildConnect(proxy, targetHost, targetPort))

  let header = await recvExact(sock, 4)
  if header[0] != '\x05':
    raise newException(ProxyProtocolError, "invalid socks5 reply header")
  let rep = header[1].byte
  if rep != 0x00:
    raise newException(ProxyConnectError, repToMessage(rep))

  # drain bound address
  let atyp = header[3].byte
  case atyp
  of 0x01:
    discard await recvExact(sock, 4)
  of 0x03:
    let lenByte = await recvExact(sock, 1)
    discard await recvExact(sock, lenByte[0].int)
  of 0x04:
    discard await recvExact(sock, 16)
  else:
    raise newException(ProxyProtocolError, "invalid address type " & $atyp)

  # drain bound port
  discard await recvExact(sock, 2)
