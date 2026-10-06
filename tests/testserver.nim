import std/[unittest, asyncdispatch, asyncnet, strutils]
import prx

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
