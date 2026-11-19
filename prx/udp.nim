import std/[net, asyncnet, asyncdispatch]
import types, common, hostport, wire, socks5

type
  UdpRelay* = ref object
    controlSock*: AsyncSocket
    udpSock*: AsyncSocket
    relayHost*: string
    relayPort*: Port
    proxy*: Proxy

  BridgeClient = ref object
    address: string
    port: Port

const maxBridgeFailures = 16

proc encodeUdpPacket*(targetHost: string, targetPort: Port, data: string, remoteDns = true): string =
  result = newStringOfCap(32 + data.len)
  result.add("\x00\x00\x00")
  result.addAddress(targetHost, targetPort, remoteDns)
  result.add(data)

proc decodeUdpPacket*(packet: string): tuple[host: string, port: Port, data: string] =
  if packet.len < 4:
    raise newException(ProxyProtocolError, "udp packet too short")
  var pos = 3
  let source = parseAddress(packet, pos)
  result = (source.host, source.port, packet[pos .. ^1])

proc associate(relay: UdpRelay, abandoned: ref bool): Future[void] {.async.} =
  let control = await asyncnet.dial(relay.proxy.host, relay.proxy.port, buffered = false)
  if abandoned[]:
    closeQuietly(control)
  else:
    relay.controlSock = control
    let bound = await udpAssociate(control, relay.proxy)

    # an unspecified relay address means the proxy host itself
    var relayIp: IpAddress
    if not tryParseIp(bound.host, relayIp):
      relayIp = resolveHost(bound.host)
    if relayIp == parseIpAddress("0.0.0.0") or relayIp == parseIpAddress("::"):
      relayIp = parseIpAddress(control.getPeerAddr()[0])
    relayIp = unmapped(relayIp)

    let domain = if relayIp.family == IpAddressFamily.IPv6: AF_INET6 else: AF_INET
    relay.udpSock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
    relay.udpSock.bindAddr(Port(0))
    relay.relayHost = $relayIp
    relay.relayPort = bound.port

proc close*(relay: UdpRelay) =
  if not relay.udpSock.isNil:
    closeQuietly(relay.udpSock)
  if not relay.controlSock.isNil:
    closeQuietly(relay.controlSock)

proc dialUdp*(proxy: Proxy, timeout = -1): Future[UdpRelay] {.async.} =
  if proxy.isNil or proxy.kind != pkSocks5:
    raise newException(ProxyProtocolError, "udp associate requires socks5")

  let t = if timeout >= 0: timeout else: proxy.timeout
  let context = "udp associate via " & joinHostPort(proxy.host, proxy.port)
  let relay = UdpRelay(proxy: proxy)
  let abandoned = new(bool)
  let pending = associate(relay, abandoned)
  var failure: ref CatchableError = nil
  try:
    if t > 0 and not await withTimeout(pending, t):
      failure = newException(ProxyTimeoutError, context & " timed out after " & $t & "ms")
    else:
      await pending
  except ProxyError as e:
    failure = e
  except CatchableError as e:
    failure = newException(ProxyConnectError, context & " failed: " & e.msg, e)

  if not failure.isNil:
    abandoned[] = true
    relay.close()
    raise failure
  result = relay

proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string, remoteDns: bool): Future[void] {.async.} =
  let packet = encodeUdpPacket(targetHost, targetPort, data, remoteDns)
  await relay.udpSock.sendTo(relay.relayHost, relay.relayPort, packet)

proc sendTo*(relay: UdpRelay, targetHost: string, targetPort: Port, data: string): Future[void] {.async.} =
  let rdns = if relay.proxy.isNil: true else: relay.proxy.remoteDns
  await relay.sendTo(targetHost, targetPort, data, rdns)

proc fromRelay(relay: UdpRelay, address: string, port: Port): bool =
  var ip: IpAddress
  port == relay.relayPort and tryParseIp(address, ip) and $unmapped(ip) == relay.relayHost

proc recvFrom*(relay: UdpRelay, maxSize = 65535): Future[tuple[host: string, port: Port, data: string]] {.async.} =
  # datagrams from anyone but the relay and fragments are skipped
  while true:
    if relay.udpSock.isClosed:
      raise newException(ProxyConnectError, "udp relay is closed")
    let dg = await relay.udpSock.recvDatagram(maxSize)
    if relay.fromRelay(dg.address, dg.port) and not isFragment(dg.data):
      return decodeUdpPacket(dg.data)

proc pumpDownstream(relay: UdpRelay, localSock: AsyncSocket, client: BridgeClient) {.async.} =
  var failures = 0
  while failures < maxBridgeFailures and not relay.udpSock.isClosed and not localSock.isClosed:
    try:
      let (_, _, data) = await relay.recvFrom()
      if client.address.len > 0 and client.port.int > 0:
        await localSock.sendTo(client.address, client.port, data)
      failures = 0
    except CatchableError:
      inc failures

proc startUdpBridge*(
  localPort: Port,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  bindAddr = "127.0.0.1"
): Future[void] {.async.} =
  let localSock = newAsyncSocket(
    if isIpv6(bindAddr): AF_INET6 else: AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  var relay: UdpRelay = nil
  try:
    localSock.bindAddr(localPort, bindAddr)
    relay = await dialUdp(proxy)

    # responses go back to whoever sent the latest datagram
    let client = BridgeClient()
    asyncCheck pumpDownstream(relay, localSock, client)

    while true:
      let dg = await localSock.recvDatagram()
      client.address = dg.address
      client.port = dg.port
      await relay.sendTo(targetHost, targetPort, dg.data)
  finally:
    if not relay.isNil:
      relay.close()
    closeQuietly(localSock)
