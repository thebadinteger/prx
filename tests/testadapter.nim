import std/[unittest, asyncdispatch, asyncnet, net, os, strutils]
import std/httpclient except Proxy
import prx

type
  EchoContext = ref object
    port: Port
    ready: bool

proc echoWorker(ctx: EchoContext) {.thread.} =
  var s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(ctx.port, "127.0.0.1")
  s.listen()
  ctx.ready = true
  for _ in 0 ..< 2:
    var c = newSocket()
    s.accept(c)
    while true:
      let line = c.recvLine()
      if line.strip.len == 0: break
    c.send("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied")
    c.close()
  s.close()

suite "prx adapter":
  test "async adapter and client":
    proc runEchoHttp(): Future[void] {.async.} =
      let s = newAsyncSocket(buffered = false)
      s.setSockOpt(OptReuseAddr, true)
      s.bindAddr(Port(19710), "127.0.0.1")
      s.listen()
      let c = await s.accept()
      while true:
        let line = await c.recvLine()
        if line.strip.len == 0: break
      await c.send("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
      c.close()
      s.close()

    let upServer = server(Port(19711), kind = skSocks5)
    asyncCheck upServer.start()

    proc testAsyncClient(): Future[void] {.async.} =
      await sleepAsync(60)
      let upstream = parseProxy("socks5://127.0.0.1:19711")
      let adapter = await startAdapterAsync(upstream)
      check adapter.port.int > 0

      let client = newAsyncHttpClient(adapter)
      let body = await client.getContent("http://127.0.0.1:19710/test")
      check body == "hello"
      client.close()
      adapter.stop()
      upServer.stop()

    waitFor runEchoHttp() and testAsyncClient()

  test "sync adapter withProxy and newHttpClient":
    var ctx = EchoContext(port: Port(19720), ready: false)
    var thr: Thread[EchoContext]
    createThread(thr, echoWorker, ctx)
    while not ctx.ready:
      os.sleep(2)

    let upAdapter = startAdapter(nil)
    check upAdapter.port.int > 0

    let upstream = upAdapter.socksProxy

    withProxy(upstream, proc(client: HttpClient) =
      let resp = client.getContent("http://127.0.0.1:19720/data")
      check resp == "proxied"
    )

    let clientAdapter = startAdapter(upstream)
    let client = newHttpClient(clientAdapter)
    let resp = client.getContent("http://127.0.0.1:19720/direct")
    check resp == "proxied"
    client.close()
    clientAdapter.stop()

    upAdapter.stop()
    joinThread(thr)
