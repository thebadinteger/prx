import std/[unittest, asyncdispatch, asyncnet, strutils]
import prx

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
