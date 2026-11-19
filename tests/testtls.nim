when defined(ssl) and not defined(nimDisableCertificateValidation):
  import std/[unittest, asyncdispatch, asyncnet, net, nativesockets, os, atomics]
  import prx
  import mock

  # self signed fixture for localhost, used only by these tests
  const
    certFile = currentSourcePath.parentDir / "certs" / "localhost.crt"
    keyFile = currentSourcePath.parentDir / "certs" / "localhost.key"

  type
    MockMode = enum
      mmTlsTarget   # clear socks5 handshake, then a tls echo endpoint
      mmHttpsProxy  # tls, http connect, echo
      mmHttpsChain  # tls, http connect, socks5 handshake, echo

    MockTls = object
      mode: MockMode
      connections: int
      port: Atomic[int]
      thread: Thread[ptr MockTls]

  proc answerSocks5(c: Socket) =
    discard c.recv(3)
    c.send("\x05\x00")
    let head = c.recv(5)
    discard c.recv(head[4].int + 2)
    c.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

  proc answerConnect(c: Socket) =
    while true:
      let line = c.recvLine()
      if line.len == 0 or line == "\r\n":
        break
    c.send("HTTP/1.1 200 Connection Established\r\n\r\n")

  proc serveClient(mode: MockMode, ctx: SslContext, c: Socket) =
    case mode
    of mmTlsTarget:
      answerSocks5(c)
      ctx.wrapConnectedSocket(c, handshakeAsServer)
    of mmHttpsProxy, mmHttpsChain:
      ctx.wrapConnectedSocket(c, handshakeAsServer)
      answerConnect(c)
      if mode == mmHttpsChain:
        answerSocks5(c)
    c.send("re:" & c.recv(4))

  proc mockWorker(m: ptr MockTls) {.thread.} =
    let ctx = newContext(verifyMode = CVerifyNone, certFile = certFile, keyFile = keyFile)
    let listener = newSocket(buffered = false)
    listener.setSockOpt(OptReuseAddr, true)
    listener.bindAddr(Port(0), "127.0.0.1")
    listener.listen()
    m.port.store(listener.getLocalAddr()[1].int)
    for _ in 0 ..< m.connections:
      # a failed test must not leave this thread waiting forever
      var readable = @[listener.getFd]
      if selectRead(readable, 10000) <= 0:
        break
      var c: Socket
      listener.accept(c)
      try:
        serveClient(m.mode, ctx, c)
      except CatchableError:
        discard
      try:
        c.close()
      except CatchableError:
        discard
    listener.close()

  proc startMock(mode: MockMode, connections: int): ptr MockTls =
    result = createShared(MockTls)
    result.mode = mode
    result.connections = connections
    createThread(result.thread, mockWorker, result)
    while result.port.load == 0:
      os.sleep(1)

  proc finish(m: ptr MockTls) =
    joinThread(m.thread)
    deallocShared(m)

  proc proxyFor(m: ptr MockTls, scheme: string): Proxy =
    # only the https proxy needs a name that matches the certificate
    let host = if scheme == "https": "localhost" else: "127.0.0.1"
    parseProxy(scheme & "://" & host & ":" & $m.port.load)

  proc echoSync(sock: Socket): string =
    sock.send("ping")
    result = sock.recv(7)
    sock.close()

  proc echoAsync(sock: AsyncSocket): Future[string] {.async.} =
    await sock.send("ping")
    result = await sock.recv(7)
    sock.close()

  suite "prx tls":
    test "tls targets are verified against the requested host":
      let m = startMock(mmTlsTarget, 4)
      let p = proxyFor(m, "socks5")
      let trusted = newContext(caFile = certFile)

      check echoSync(dialTls(p, "localhost", Port(443), sslContext = trusted)) == "re:ping"
      expect ProxyConnectError:
        discard dialTls(p, "wrong.example", Port(443), sslContext = trusted)

      proc run() {.async.} =
        let sock = await dialTlsAsync(p, "localhost", Port(443), sslContext = trusted)
        check (await echoAsync(sock)) == "re:ping"
        checkRaises ProxyConnectError:
          discard await dialTlsAsync(p, "wrong.example", Port(443), sslContext = trusted)

      waitFor run()
      finish(m)

    test "untrusted certificates are rejected by default":
      let m = startMock(mmTlsTarget, 2)
      let p = proxyFor(m, "socks5")
      expect ProxyConnectError:
        discard dialTls(p, "localhost", Port(443))

      proc run() {.async.} =
        checkRaises ProxyConnectError:
          discard await dialTlsAsync(p, "localhost", Port(443))

      waitFor run()
      finish(m)

    test "async tls handshake is bound by the dial timeout":
      proc run() {.async.} =
        let listener = listenLocal()
        asyncCheck serveOnce(listener, proc(c: AsyncSocket) {.async.} =
          discard await c.recv(3)
          await c.send("\x05\x00")
          let head = await c.recv(5)
          discard await c.recv(head[4].int + 2)
          await c.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
          # the tunnel is open but the tls peer never answers
          while (await c.recv(4096)).len > 0:
            discard
        )
        checkRaises ProxyTimeoutError:
          discard await dialTlsAsync(proxyFor(listener), "localhost", Port(443), timeout = 300)

      waitFor run()

    test "https proxy":
      let m = startMock(mmHttpsProxy, 3)
      let p = proxyFor(m, "https")
      let trusted = newContext(caFile = certFile)

      check echoSync(dial(p, "target.local", Port(80), sslContext = trusted)) == "re:ping"
      expect ProxyConnectError:
        discard dial(p, "target.local", Port(80))

      proc run() {.async.} =
        let sock = await dialAsync(p, "target.local", Port(80), sslContext = trusted)
        check (await echoAsync(sock)) == "re:ping"

      waitFor run()
      finish(m)

    test "https proxy at the head of a chain":
      let m = startMock(mmHttpsChain, 2)
      let chain = @[proxyFor(m, "https"), parseProxy("socks5://next.hop:1080")]
      let trusted = newContext(caFile = certFile)

      check echoSync(dial(chain, "target.local", Port(80), sslContext = trusted)) == "re:ping"

      proc run() {.async.} =
        let sock = await dialAsync(chain, "target.local", Port(80), sslContext = trusted)
        check (await echoAsync(sock)) == "re:ping"

      waitFor run()
      finish(m)
