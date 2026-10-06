import std/[unittest, asyncdispatch, asyncnet, net, os]
import prx

suite "prx socks5 mock e2e":
  test "socks5 handshake and connect async":
    proc runMockServer(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19050), "127.0.0.1")
      server.listen()

      let client = await server.accept()

      # greeting 4 bytes for user pass
      let greet = await client.recv(4)
      check greet[0] == '\x05'
      await client.send("\x05\x02")

      # auth subneg 14 bytes
      let authReq = await client.recv(14)
      check authReq[0] == '\x01'
      await client.send("\x01\x00")

      # connect cmd
      let cmdReq = await client.recv(21)
      check cmdReq[0] == '\x05'
      check cmdReq[1] == '\x01'
      # reply success
      await client.send("\x05\x00\x00\x01\x7F\x00\x00\x01\x1F\x90")

      # echo payload
      let msg = await client.recv(4)
      check msg == "ping"
      await client.send("pong")
      client.close()
      server.close()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(50)
      let p = parseProxy("socks5://alice:secret@127.0.0.1:19050")
      let sock = await dialAsync(p, "target.local", Port(8080))
      await sock.send("ping")
      let resp = await sock.recv(4)
      check resp == "pong"
      sock.close()

    waitFor runMockServer() and runClient()

suite "prx socks4 mock e2e":
  test "socks4 handshake and connect async":
    proc runMockServer(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19040), "127.0.0.1")
      server.listen()

      let client = await server.accept()

      # read socks4 connect req 9 bytes
      let req = await client.recv(9)
      check req[0] == '\x04'
      check req[1] == '\x01'

      # send 0x5a success response
      await client.send("\x00\x5A\x00\x50\x7F\x00\x00\x01")

      let msg = await client.recv(5)
      check msg == "hello"
      await client.send("world")
      client.close()
      server.close()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(50)
      let p = parseProxy("socks4://127.0.0.1:19040")
      let sock = await dialAsync(p, "127.0.0.1", Port(80))
      await sock.send("hello")
      let resp = await sock.recv(5)
      check resp == "world"
      sock.close()

    waitFor runMockServer() and runClient()

suite "prx sync dial":
  test "socks5 sync dial":
    proc syncMockServer() {.thread.} =
      let server = newSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19150), "127.0.0.1")
      server.listen()

      var client = newSocket(buffered = false)
      server.accept(client)

      var greet = newString(3)
      discard client.recv(greet[0].addr, 3)
      client.send("\x05\x00")

      var req = newString(21)
      discard client.recv(req[0].addr, 21)
      client.send("\x05\x00\x00\x01\x7F\x00\x00\x01\x1F\x90")

      var msg = newString(4)
      discard client.recv(msg[0].addr, 4)
      client.send("pong")

      client.close()
      server.close()

    var thr: Thread[void]
    createThread(thr, syncMockServer)
    sleep(100)

    let p = parseProxy("socks5://127.0.0.1:19150")
    let sock = dial(p, "target.local", Port(8080))
    sock.send("ping")
    var buf = newString(4)
    discard sock.recv(buf[0].addr, 4)
    check buf == "pong"
    sock.close()
    joinThread(thr)

suite "prx socks5 remote dns handshake":
  test "socks5 local dns vs remote dns handshake":
    proc runMockServer(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19650), "127.0.0.1")
      server.listen()

      # local dns connection
      let c1 = await server.accept()
      discard await c1.recv(3)
      await c1.send("\x05\x00")
      let cmd1 = await c1.recv(10)
      check cmd1[0] == '\x05'
      check cmd1[1] == '\x01'
      check cmd1[3] == '\x01'
      await c1.send("\x05\x00\x00\x01\x7F\x00\x00\x01\x1F\x90")
      c1.close()

      # remote dns connection
      let c2 = await server.accept()
      discard await c2.recv(3)
      await c2.send("\x05\x00")
      let cmd2 = await c2.recv(4)
      check cmd2[0] == '\x05'
      check cmd2[1] == '\x01'
      check cmd2[3] == '\x03'
      let dlen = (await c2.recv(1))[0].int
      let domain = await c2.recv(dlen)
      check domain == "localhost"
      discard await c2.recv(2)
      await c2.send("\x05\x00\x00\x01\x7F\x00\x00\x01\x1F\x90")
      c2.close()

      server.close()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(50)
      let pLocalDns = parseProxy("socks5://127.0.0.1:19650?rdns=0")
      let s1 = await dialAsync(pLocalDns, "localhost", Port(80))
      s1.close()

      let pRemoteDns = parseProxy("socks5://127.0.0.1:19650?rdns=1")
      let s2 = await dialAsync(pRemoteDns, "localhost", Port(80))
      s2.close()

    waitFor runMockServer() and runClient()
