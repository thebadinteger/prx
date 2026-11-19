import std/[unittest, asyncdispatch, asyncnet, strutils]
import prx
import mock

suite "prx proxy server":
  test "server socks5 with auth":
    proc runEcho(): Future[void] {.async.} =
      let s = newAsyncSocket(buffered = false)
      s.setSockOpt(OptReuseAddr, true)
      s.bindAddr(Port(19501), "127.0.0.1")
      s.listen()
      let c = await s.accept()
      let msg = await c.recv(4)
      await c.send(msg)
      c.close()
      s.close()

    let srv = server(Port(19500), kind = skSocks5)
    srv.setAuth("alice", "secret")
    asyncCheck srv.start()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(80)
      let pGood = parseProxy("socks5://alice:secret@127.0.0.1:19500")
      let sock = await dialAsync(pGood, "127.0.0.1", Port(19501))
      await sock.send("echo")
      let resp = await sock.recv(4)
      check resp == "echo"
      sock.close()

      let pBad = parseProxy("socks5://alice:wrong@127.0.0.1:19500")
      var failed = false
      try:
        let sBad = await dialAsync(pBad, "127.0.0.1", Port(19501))
        sBad.close()
      except ProxyAuthError:
        failed = true
      check failed
      srv.stop()

    waitFor runEcho() and runClient()

  test "server unified combo port":
    proc runEcho(): Future[void] {.async.} =
      let s = newAsyncSocket(buffered = false)
      s.setSockOpt(OptReuseAddr, true)
      s.bindAddr(Port(19531), "127.0.0.1")
      s.listen()
      for _ in 0 ..< 3:
        let c = await s.accept()
        let msg = await c.recv(4)
        await c.send(msg)
        c.close()
      s.close()

    let srv = server(Port(19530), kind = skAuto)
    asyncCheck srv.start()

    proc runClients(): Future[void] {.async.} =
      await sleepAsync(80)

      # 1 socks5
      let pSocks5 = parseProxy("socks5://127.0.0.1:19530")
      let s5 = await dialAsync(pSocks5, "127.0.0.1", Port(19531))
      await s5.send("sck5")
      check (await s5.recv(4)) == "sck5"
      s5.close()

      # 2 socks4
      let pSocks4 = parseProxy("socks4://127.0.0.1:19530")
      let s4 = await dialAsync(pSocks4, "127.0.0.1", Port(19531))
      await s4.send("sck4")
      check (await s4.recv(4)) == "sck4"
      s4.close()

      # 3 http connect
      let pHttp = parseProxy("http://127.0.0.1:19530")
      let sh = await dialAsync(pHttp, "127.0.0.1", Port(19531))
      await sh.send("http")
      check (await sh.recv(4)) == "http"
      sh.close()

    waitFor runEcho() and runClients()

  test "listen resolves an ephemeral port before serving":
    let srv = server(Port(0))
    srv.listen()
    check srv.running
    check srv.port != Port(0)
    srv.stop()
    check not srv.running

  test "http rejects malformed targets":
    proc run() {.async.} =
      let srv = startServer(skHttp)
      for request in ["CONNECT example.com:99999 HTTP/1.1", "CONNECT :443 HTTP/1.1",
                      "GET /relative HTTP/1.1", "GET ftp://example.com/ HTTP/1.1", "garbage"]:
        let s = await asyncnet.dial("127.0.0.1", srv.port, buffered = false)
        await s.send(request & "\r\n\r\n")
        check (await s.recvLine()).startsWith("HTTP/1.1 400")
        s.close()
      srv.stop()

    waitFor run()

  test "http forward isolates each request":
    proc run() {.async.} =
      var seen = ""
      let origin = listenLocal()
      asyncCheck serveOnce(origin, proc(c: AsyncSocket) {.async.} =
        seen = await recvHead(c)
        await c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      )
      let srv = startServer(skHttp)
      srv.setAuth("alice", "secret")

      let s = await asyncnet.dial("127.0.0.1", srv.port, buffered = false)
      await s.send("GET http://127.0.0.1:" & $origin.localPort.int & "/path?q=1 HTTP/1.1\r\n" &
        "Host: 127.0.0.1\r\n" &
        "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n" &
        "Proxy-Connection: keep-alive\r\n" &
        "Connection: keep-alive\r\n\r\n")
      let response = await recvAll(s)
      s.close()
      srv.stop()

      check response.startsWith("HTTP/1.1 200 OK")
      check response.endsWith("ok")
      check seen.startsWith("GET /path?q=1 HTTP/1.1\n")
      check "Connection: close" in seen
      check "keep-alive" notin seen
      check "Proxy-Authorization" notin seen

    waitFor run()

  test "silent clients are dropped after the handshake timeout":
    proc run() {.async.} =
      let srv = server(Port(0))
      srv.handshakeTimeout = 150
      srv.listen()
      asyncCheck srv.serve()

      let s = await asyncnet.dial("127.0.0.1", srv.port, buffered = false)
      let closed = recvAll(s)
      check await withTimeout(closed, 5000)
      s.close()
      srv.stop()

    waitFor run()

  test "half closed clients still receive the reply":
    proc run() {.async.} =
      let origin = listenLocal()
      asyncCheck serveOnce(origin, proc(c: AsyncSocket) {.async.} =
        let request = await recvAll(c)
        await c.send("got " & request)
      )
      let srv = startServer(skSocks5)

      let s = await dialAsync(proxyFor(srv), "127.0.0.1", origin.localPort)
      await s.send("request")
      finishWrite(s)
      let reply = recvAll(s)
      check await withTimeout(reply, 5000)
      check reply.read == "got request"
      s.close()
      srv.stop()

    waitFor run()

  test "unreachable targets are reported to the client":
    proc run() {.async.} =
      let srv = startServer()
      let target = closedPort()
      for scheme in ["socks5", "socks4", "http"]:
        checkRaises ProxyConnectError:
          discard await dialAsync(proxyFor(srv, scheme), "127.0.0.1", target)
      srv.stop()

    waitFor run()

  test "socks5 success reply carries the bound address":
    proc run() {.async.} =
      let origin = listenLocal()
      asyncCheck serveOnce(origin, proc(c: AsyncSocket) {.async.} =
        discard await recvAll(c)
      )
      let srv = startServer(skSocks5)
      let s = await asyncnet.dial("127.0.0.1", srv.port, buffered = false)
      await s.send("\x05\x01\x00")
      check (await s.recv(2)) == "\x05\x00"
      let port = origin.localPort.toBytes
      await s.send("\x05\x01\x00\x01\x7F\x00\x00\x01" & port[0].char & port[1].char)
      let reply = await s.recv(10)
      check reply.len == 10
      check reply[0 .. 7] == "\x05\x00\x00\x01\x7F\x00\x00\x01"
      check toPort(reply[8].byte, reply[9].byte) != Port(0)
      s.close()
      srv.stop()

    waitFor run()

  test "socks5 rejects hosts the resolver would truncate":
    proc run() {.async.} =
      var filtered: seq[string] = @[]
      let srv = startServer(skSocks5)
      srv.setFilter(proc(host: string, port: Port): bool =
        filtered.add(host)
        true
      )
      let s = await asyncnet.dial("127.0.0.1", srv.port, buffered = false)
      await s.send("\x05\x01\x00")
      check (await s.recv(2)) == "\x05\x00"
      await s.send("\x05\x01\x00\x03\x0Dlocalhost\x00.ok\x00\x50")
      let reply = await s.recv(10)
      check reply.len == 10
      check reply[1] == '\x01'
      check filtered.len == 0
      s.close()
      srv.stop()

    waitFor run()

  test "filter denies requests on every protocol":
    proc run() {.async.} =
      let srv = startServer()
      srv.setFilter(proc(host: string, port: Port): bool = false)
      for scheme in ["socks5", "socks4", "http"]:
        checkRaises ProxyConnectError:
          discard await dialAsync(proxyFor(srv, scheme), "127.0.0.1", Port(80))
      srv.stop()

    waitFor run()
