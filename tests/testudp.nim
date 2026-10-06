import std/[unittest, asyncdispatch, asyncnet, net]
import prx

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
