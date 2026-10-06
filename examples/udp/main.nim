import std/asyncdispatch
import prx

proc main() {.async.} =
  let p = proxy("socks5://127.0.0.1:1080")
  try:
    let relay = await dialUdp(p)

    # dns query for example.com
    let dnsQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

    # send to 8.8.8.8:53 via socks5 udp associate
    await relay.sendTo("8.8.8.8", Port(53), dnsQuery)

    let (srcHost, srcPort, data) = await relay.recvFrom()
    echo "received ", data.len, " bytes from ", srcHost, ":", srcPort.int
    relay.close()
  except CatchableError as e:
    echo "udp associate error: ", e.msg

waitFor main()
