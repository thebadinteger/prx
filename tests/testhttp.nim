import std/[unittest, asyncdispatch, asyncnet, strutils]
import prx
import mock

suite "prx http connect mock e2e":
  test "http connect tunnel async":
    proc runMockServer(): Future[void] {.async.} =
      let server = newAsyncSocket(buffered = false)
      server.setSockOpt(OptReuseAddr, true)
      server.bindAddr(Port(19080), "127.0.0.1")
      server.listen()

      let client = await server.accept()

      var req = ""
      while true:
        let line = await client.recvLine()
        req.add(line & "\n")
        if line.strip.len == 0:
          break

      check "CONNECT mytarget.com:443 HTTP/1.1" in req
      check "Proxy-Authorization: Basic " in req

      # 200 connection established
      await client.send("HTTP/1.1 200 Connection Established\r\n\r\n")

      let msg = await client.recv(4)
      check msg == "test"
      await client.send("echo")
      client.close()
      server.close()

    proc runClient(): Future[void] {.async.} =
      await sleepAsync(50)
      let p = parseProxy("http://admin:pass123@127.0.0.1:19080")
      let sock = await dialAsync(p, "mytarget.com", Port(443))
      await sock.send("test")
      let resp = await sock.recv(4)
      check resp == "echo"
      sock.close()

    waitFor runMockServer() and runClient()

suite "prx http connect validation":
  test "connect request brackets ipv6 targets":
    let p = parseProxy("http://127.0.0.1:8080")
    let req = buildConnectRequest(p, "2001:db8::1", Port(443))
    check req.startsWith("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n")
    check "Host: [2001:db8::1]:443\r\n" in req
    check buildConnectRequest(p, "[::1]", Port(443)).startsWith("CONNECT [::1]:443 ")

  test "connect request rejects header injection":
    let p = parseProxy("http://127.0.0.1:8080")
    expect ProxyProtocolError:
      discard buildConnectRequest(p, "a\r\nX-Injected: 1", Port(80))
    expect ProxyProtocolError:
      discard buildConnectRequest(p, "", Port(80))

  test "proxy auth challenge raises an auth error":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await recvHead(c)
        await c.send("HTTP/1.1 407 Proxy Authentication Required\r\n" &
          "Proxy-Authenticate: Basic realm=\"mock\"\r\n\r\n")
      )
      checkRaises ProxyAuthError:
        discard await dialAsync(proxyFor(listener, "http"), "mytarget.com", Port(443))

    waitFor run()

  test "truncated proxy response is a connect error":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await recvHead(c)
        await c.send("HTTP/1.1 200 Connection Established\r\n")
      )
      checkRaises ProxyConnectError:
        discard await dialAsync(proxyFor(listener, "http"), "mytarget.com", Port(443))

    waitFor run()

  test "non http reply is a protocol error":
    proc run() {.async.} =
      let listener = listenLocal()
      asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
        discard await recvHead(c)
        await c.send("SSH-2.0-OpenSSH_9.6\r\n\r\n")
      )
      checkRaises ProxyProtocolError:
        discard await dialAsync(proxyFor(listener, "http"), "mytarget.com", Port(443))

    waitFor run()
