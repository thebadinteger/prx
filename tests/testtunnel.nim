import std/[unittest, asyncdispatch, asyncnet, strutils]
import prx

suite "prx tunnel pipe e2e":
  test "pipe between two sockets":
    proc runServer(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19090), "127.0.0.1")
      server.listen()

      let c1 = await server.accept()
      let c2 = await server.accept()

      asyncCheck pipe(c1, c2)
      server.close()

    proc runClients(): Future[void] {.async.} =
      await sleepAsync(50)
      let s1 = await asyncnet.dial("127.0.0.1", Port(19090), buffered = false)
      let s2 = await asyncnet.dial("127.0.0.1", Port(19090), buffered = false)

      await s1.send("piped-data")
      let recvd = await s2.recv(10)
      check recvd == "piped-data"
      s1.close()
      s2.close()

    waitFor runServer() and runClients()

suite "prx proxy chaining":
  test "chain http connect to socks5":
    proc runHttpProxy(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19201), "127.0.0.1")
      server.listen()

      let client = await server.accept()
      while true:
        let line = await client.recvLine()
        if line.strip.len == 0: break
      await client.send("HTTP/1.1 200 Connection Established\r\n\r\n")

      let hop2 = await asyncnet.dial("127.0.0.1", Port(19202), buffered = false)
      asyncCheck pipe(client, hop2)
      server.close()

    proc runSocks5Proxy(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19202), "127.0.0.1")
      server.listen()

      let client = await server.accept()
      discard await client.recv(3)
      await client.send("\x05\x00")
      discard await client.recv(21)
      await client.send("\x05\x00\x00\x01\x7F\x00\x00\x01\x1F\x90")

      let msg = await client.recv(4)
      check msg == "ping"
      await client.send("pong")
      client.close()
      server.close()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(80)
      let p1 = parseProxy("http://127.0.0.1:19201")
      let p2 = parseProxy("socks5://127.0.0.1:19202")
      let sock = await dialAsync([p1, p2], "target.local", Port(8080))
      await sock.send("ping")
      let resp = await sock.recv(4)
      check resp == "pong"
      sock.close()

    waitFor runHttpProxy() and runSocks5Proxy() and runClient()
