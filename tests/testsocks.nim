import std/[unittest, asyncdispatch, asyncnet, net, os, strutils, monotimes, times]
import prx
import mock

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

proc untilClosed(client: AsyncSocket) {.async.} =
  while (await client.recv(64)).len > 0:
    discard

suite "prx handshake validation":
  test "socks5 rejects oversized fields instead of truncating":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, untilClosed)
      checkRaises ProxyProtocolError:
        discard await dialAsync(proxyFor(listener), repeat('a', 256), Port(80))

      let authListener = listenLocal()
      asyncCheck serveOnce(authListener, untilClosed)
      let p = proxyFor(authListener)
      p.username = repeat('u', 256)
      checkRaises ProxyAuthError:
        discard await dialAsync(p, "target.local", Port(80))

    waitFor run()

  test "socks5 rejects an auth method that was not offered":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await c.recv(3)
        await c.send("\x05\x02")
        await untilClosed(c)
      )
      checkRaises ProxyAuthError:
        discard await dialAsync(proxyFor(listener), "target.local", Port(80))

    waitFor run()

  test "socks4 rejects a malformed reply":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await c.recv(9)
        await c.send("\x04\x5A\x00\x50\x7F\x00\x00\x01")
        await untilClosed(c)
      )
      checkRaises ProxyProtocolError:
        discard await dialAsync(proxyFor(listener, "socks4"), "127.0.0.1", Port(80))

    waitFor run()

  test "socks4 resolves names locally and socks4a sends them":
    proc run() {.async.} =
      var strict, extended = ""
      let strictListener = listenLocal()
      asyncCheck serveOnce(strictListener, proc(c: AsyncSocket) {.async.} =
        strict = await c.recv(9)
        await c.send("\x00\x5A\x00\x00\x00\x00\x00\x00")
      )
      let s1 = await dialAsync(
        newProxy("127.0.0.1", strictListener.localPort, pkSocks4), "localhost", Port(80))
      s1.close()
      check strict == "\x04\x01\x00\x50\x7F\x00\x00\x01\x00"

      let extendedListener = listenLocal()
      asyncCheck serveOnce(extendedListener, proc(c: AsyncSocket) {.async.} =
        extended = await c.recv(19)
        await c.send("\x00\x5A\x00\x00\x00\x00\x00\x00")
      )
      let s2 = await dialAsync(
        newProxy("127.0.0.1", extendedListener.localPort, pkSocks4a), "localhost", Port(80))
      s2.close()
      check extended == "\x04\x01\x00\x50\x00\x00\x00\x01\x00localhost\x00"

    waitFor run()

  test "socks4 has no ipv6 addressing":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, untilClosed)
      checkRaises ProxyProtocolError:
        discard await dialAsync(proxyFor(listener, "socks4"), "::1", Port(80))

    waitFor run()

suite "prx dial timeouts":
  test "async dial gives up after the proxy timeout":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, untilClosed)
      let p = proxyFor(listener)
      p.timeout = 200
      let started = getMonoTime()
      checkRaises ProxyTimeoutError:
        discard await dialAsync(p, "target.local", Port(80))
      check (getMonoTime() - started).inMilliseconds < 5000

    waitFor run()

  test "sync dial reports a proxy timeout":
    # connections are accepted by the kernel backlog and never answered
    let listener = newSocket(buffered = false)
    listener.bindAddr(Port(0), "127.0.0.1")
    listener.listen()
    let p = parseProxy("socks5://127.0.0.1:" & $listener.getLocalAddr()[1].int)
    expect ProxyTimeoutError:
      discard dial(p, "target.local", Port(80), timeout = 200)
    listener.close()

  test "sync dial reports a refused proxy before the timeout runs out":
    let p = parseProxy("socks5://127.0.0.1:" & $closedPort().int)
    let started = getMonoTime()
    expect ProxyConnectError:
      discard dial(p, "target.local", Port(80), timeout = 15000)
    check (getMonoTime() - started).inMilliseconds < 10000

  test "io failures surface as proxy errors":
    proc run() {.async.} =
      let p = parseProxy("socks5://127.0.0.1:" & $closedPort().int)
      p.timeout = 3000
      checkRaises ProxyError:
        discard await dialAsync(p, "target.local", Port(80))

      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await c.recv(3)
      )
      checkRaises ProxyConnectError:
        discard await dialAsync(proxyFor(listener), "target.local", Port(80))

    waitFor run()
