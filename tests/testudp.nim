import std/[unittest, asyncdispatch, asyncnet, net]
import prx
import mock

proc echoDatagrams(sock: AsyncSocket) {.async.} =
  try:
    while true:
      let dg = await sock.recvDatagram()
      await sock.sendTo(dg.address, dg.port, dg.data)
  except CatchableError:
    discard

proc newUdpSocket(): AsyncSocket =
  result = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  result.bindAddr(Port(0), "127.0.0.1")

suite "prx udp associate":
  test "socks5 udp associate e2e":
    proc runEchoUdp(): Future[void] {.async.} =
      let s = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
      s.bindAddr(Port(19600), "127.0.0.1")
      let dg = await s.recvDatagram()
      check dg.data == "ping udp"
      await s.sendTo(dg.address, dg.port, "pong udp")
      s.close()

    let srv = server(Port(19601), kind = skSocks5)
    asyncCheck srv.start()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(80)
      let p = parseProxy("socks5://127.0.0.1:19601")
      let relay = await dialUdp(p)

      await relay.sendTo("127.0.0.1", Port(19600), "ping udp")
      let (_, _, data) = await relay.recvFrom()
      check data == "pong udp"

      relay.close()
      srv.stop()

    waitFor runEchoUdp() and runClient()

  test "packet codec round trips and rejects truncated input":
    let (host, port, data) = decodeUdpPacket(encodeUdpPacket("example.com", Port(53), "payload"))
    check host == "example.com"
    check port == Port(53)
    check data == "payload"

    let v6 = decodeUdpPacket(encodeUdpPacket("2001:db8::1", Port(443), ""))
    check v6.host == "2001:db8::1"
    check v6.data == ""

    for packet in ["", "\x00\x00\x00", "\x00\x00\x00\x03\xFFaaaaa", "\x00\x00\x00\x04aaaaaaaa",
                   "\x00\x00\x00\x01\x7F\x00\x00\x01\x00", "\x00\x00\x00\x09aaaaaaaaaa"]:
      expect ProxyProtocolError:
        discard decodeUdpPacket(packet)

  test "relay only serves the associated client":
    proc run() {.async.} =
      let target = newUdpSocket()
      asyncCheck echoDatagrams(target)
      let targetPort = target.getLocalAddr()[1]
      let srv = startServer(skSocks5)
      let relay = await dialUdp(proxyFor(srv))

      await relay.sendTo("127.0.0.1", targetPort, "first")
      check (await relay.recvFrom()).data == "first"

      # none of these may reach the target or take the relay down
      let intruder = newUdpSocket()
      await intruder.sendTo(relay.relayHost, relay.relayPort,
        encodeUdpPacket("127.0.0.1", targetPort, "intruder"))
      await relay.udpSock.sendTo(relay.relayHost, relay.relayPort, "\x00\x00\x00\x03\xFFaaaaa")
      await relay.udpSock.sendTo(relay.relayHost, relay.relayPort,
        "\x00\x00\x01" & encodeUdpPacket("127.0.0.1", targetPort, "fragment")[3 .. ^1])

      await relay.sendTo("127.0.0.1", targetPort, "second")
      let reply = relay.recvFrom()
      check await withTimeout(reply, 5000)
      check reply.read.data == "second"

      intruder.close()
      relay.close()
      target.close()
      srv.stop()

    waitFor run()

  test "relay reaches ipv6 targets":
    var target: AsyncSocket = nil
    try:
      target = newAsyncSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
      target.bindAddr(Port(0), "::1")
    except CatchableError:
      if not target.isNil:
        target.close()
      target = nil

    if target.isNil:
      skip()
    else:
      proc run() {.async.} =
        asyncCheck echoDatagrams(target)
        let srv = startServer(skSocks5)
        let relay = await dialUdp(proxyFor(srv))

        await relay.sendTo("::1", target.getLocalAddr()[1], "over ipv6")
        let reply = relay.recvFrom()
        check await withTimeout(reply, 5000)
        check reply.read.host == "::1"
        check reply.read.data == "over ipv6"

        relay.close()
        target.close()
        srv.stop()

      waitFor run()

  test "client ignores datagrams that do not come from the relay":
    proc run() {.async.} =
      let target = newUdpSocket()
      asyncCheck echoDatagrams(target)
      let targetPort = target.getLocalAddr()[1]
      let srv = startServer(skSocks5)
      let relay = await dialUdp(proxyFor(srv))

      let stranger = newUdpSocket()
      await stranger.sendTo("127.0.0.1", relay.udpSock.getLocalAddr()[1],
        encodeUdpPacket("127.0.0.1", targetPort, "spoofed"))
      await relay.sendTo("127.0.0.1", targetPort, "genuine")
      let reply = relay.recvFrom()
      check await withTimeout(reply, 5000)
      check reply.read.data == "genuine"

      stranger.close()
      relay.close()
      target.close()
      srv.stop()

    waitFor run()

  test "udp associate is refused when an upstream proxy is set":
    proc run() {.async.} =
      let upstream = startServer(skSocks5)
      let srv = server(Port(0), kind = skSocks5, upstream = proxyFor(upstream))
      srv.listen()
      asyncCheck srv.serve()
      checkRaises ProxyConnectError:
        discard await dialUdp(proxyFor(srv))
      srv.stop()
      upstream.stop()

    waitFor run()
