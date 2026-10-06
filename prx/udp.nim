import std/[net, asyncnet, asyncdispatch, strutils, nativesockets]
import types, common

type
  UdpRelay* = ref object
    controlSock*: AsyncSocket
    udpSock*: AsyncSocket
    relayHost*: string
    relayPort*: Port
    proxy*: Proxy

proc encodeUdpPacket*(targetHost: string, targetPort: Port, data: string, remoteDns = true): string =
  result = newStringOfCap(32 + data.len)
  result.add("\x00\x00\x00")
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
  elif remoteDns:
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
  result.add(data)


proc decodeUdpPacket*(packet: string): tuple[host: string, port: Port, data: string] =
  if packet.len < 10:
    raise newException(ProxyProtocolError, "udp packet too short")

  let atyp = packet[3].byte
  var offset = 4
  var targetHost = ""

  case atyp
  of 0x01:
    let a = packet[4].byte.int
    let b = packet[5].byte.int
    let c = packet[6].byte.int
    let d = packet[7].byte.int
    targetHost = $a & "." & $b & "." & $c & "." & $d
    offset = 8
  of 0x03:
    let dlen = packet[4].int
    targetHost = packet[5 ..< 5 + dlen]
    offset = 5 + dlen
  of 0x04:
    var parts: seq[string] = @[]
    for i in countup(4, 18, 2):
      let val = (packet[i].byte.int shl 8) or packet[i + 1].byte.int
      parts.add(toHex(val, 1).toLowerAscii)
    targetHost = parts.join(":")
    offset = 20
  else:
    raise newException(ProxyProtocolError, "invalid udp address type " & $atyp)

  let targetPort = toPort(packet[offset].byte, packet[offset + 1].byte)
  offset += 2
  let data = packet[offset .. ^1]
  result = (targetHost, targetPort, data)

proc buildGreeting(hasAuth: bool): string =
  if hasAuth: "\x05\x02\x00\x02" else: "\x05\x01\x00"

proc buildAuth(username, password: string): string =
  let ulen = min(username.len, 255)
  let plen = min(password.len, 255)
  result = newStringOfCap(3 + ulen + plen)
  result.add('\x01')
  result.add(ulen.char)
  if ulen > 0: result.add(username[0 ..< ulen])
  result.add(plen.char)
  if plen > 0: result.add(password[0 ..< plen])

proc dialUdp*(proxy: Proxy): Future[UdpRelay] {.async.} =
  if proxy.kind != pkSocks5:
    raise newException(ProxyProtocolError, "udp associate requires socks5")

  let controlSock = await asyncnet.dial(proxy.host, proxy.port, buffered = false)

  # negotiate authentication
  let hasAuth = proxy.username.len > 0
  await controlSock.send(buildGreeting(hasAuth))

  let methodResp = await recvExact(controlSock, 2)
  if methodResp[0] != '\x05':
    controlSock.close
    raise newException(ProxyProtocolError, "invalid socks5 greeting reply")

  let selectedMethod = methodResp[1].byte
  if selectedMethod == 0xFF:
    controlSock.close
    raise newException(ProxyAuthError, "no acceptable auth methods")

  if selectedMethod == 0x02:
    await controlSock.send(buildAuth(proxy.username, proxy.password))
    let authResp = await recvExact(controlSock, 2)
    if authResp[1].byte != 0x00:
      controlSock.close
      raise newException(ProxyAuthError, "socks5 authentication failed")

  # send udp associate command
  await controlSock.send("\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")

  let replyHead = await recvExact(controlSock, 4)
  if replyHead[0] != '\x05':
    controlSock.close
    raise newException(ProxyProtocolError, "invalid socks5 reply")

  if replyHead[1].byte != 0x00:
    controlSock.close
    raise newException(ProxyConnectError, "socks5 udp associate rejected")

  var relayHost = ""
  let atyp = replyHead[3].byte
  case atyp
  of 0x01:
    let ipBytes = await recvExact(controlSock, 4)
    relayHost = $ipBytes[0].int & "." & $ipBytes[1].int & "." & $ipBytes[2].int & "." & $ipBytes[3].int
  of 0x03:
    let dlen = (await recvExact(controlSock, 1))[0].int
    relayHost = await recvExact(controlSock, dlen)
  of 0x04:
    let ipBytes = await recvExact(controlSock, 16)
    var parts: seq[string] = @[]
    for i in countup(0, 14, 2):
      let val = (ipBytes[i].int shl 8) or ipBytes[i + 1].int
      parts.add(toHex(val, 1).toLowerAscii)
    relayHost = parts.join(":")
  else:
    controlSock.close
    raise newException(ProxyProtocolError, "invalid bound address type")

  let portBytes = await recvExact(controlSock, 2)
  let relayPort = toPort(portBytes[0].byte, portBytes[1].byte)

  if relayHost == "0.0.0.0" or relayHost == "::" or relayHost.len == 0:
    relayHost = proxy.host

  let udpSock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  udpSock.bindAddr(Port(0), "127.0.0.1")

  result = UdpRelay(
    controlSock: controlSock,
    udpSock: udpSock,
    relayHost: relayHost,
    relayPort: relayPort,
    proxy: proxy
  )

proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string, remoteDns: bool): Future[void] {.async.} =
  let packet = encodeUdpPacket(targetHost, targetPort, data, remoteDns)
  await relay.udpSock.sendTo(relay.relayHost, relay.relayPort, packet)

proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string): Future[void] {.async.} =
  let rdns = if relay.proxy.isNil: true else: relay.proxy.remoteDns
  await relay.sendTo(targetHost, targetPort, data, rdns)

proc recvFrom*(relay: UdpRelay, maxSize = 65535): Future[tuple[host: string, port: Port, data: string]] {.async.} =
  let dg = await relay.udpSock.recvDatagram(maxSize)
  result = decodeUdpPacket(dg.data)

proc close*(relay: UdpRelay) =
  if not relay.udpSock.isNil:
    relay.udpSock.close
  if not relay.controlSock.isNil:
    relay.controlSock.close

proc startUdpBridge*(
  localPort: Port,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  bindAddr = "127.0.0.1"
): Future[void] {.async.} =
  let localSock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  localSock.bindAddr(localPort, bindAddr)

  let relay = await dialUdp(proxy)

  # pump responses back to local client
  var lastClientAddr = ""
  var lastClientPort = Port(0)

  proc pumpDownstream(): Future[void] {.async.} =
    while true:
      let (_, _, data) = await relay.recvFrom()
      if lastClientAddr.len > 0 and lastClientPort.int > 0:
        await localSock.sendTo(lastClientAddr, lastClientPort, data)

  asyncCheck pumpDownstream()

  while true:
    let dg = await localSock.recvDatagram()
    lastClientAddr = dg.address
    lastClientPort = dg.port
    await relay.sendTo(targetHost, targetPort, dg.data)

