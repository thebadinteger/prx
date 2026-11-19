import std/[asyncdispatch, asyncnet, net, unittest]
import prx

when defined(windows):
  from std/winlean import shutdown
  const shutWrite = 1.cint
else:
  from std/posix import shutdown, SHUT_WR
  let shutWrite = SHUT_WR

type MockHandler* = proc(client: AsyncSocket): Future[void] {.closure.}

template checkRaises*(exc: typedesc, body: untyped) =
  var raised = false
  try:
    body
  except exc:
    raised = true
  check raised

proc listenLocal*(): AsyncSocket =
  result = newAsyncSocket(buffered = false)
  result.setSockOpt(OptReuseAddr, true)
  result.bindAddr(Port(0), "127.0.0.1")
  result.listen()

proc localPort*(sock: AsyncSocket): Port =
  sock.getLocalAddr()[1]

proc serveOnce*(listener: AsyncSocket, handler: MockHandler) {.async.} =
  let client = await listener.accept()
  try:
    await handler(client)
  finally:
    client.close()
    listener.close()

proc recvHead*(client: AsyncSocket): Future[string] {.async.} =
  ## reads an http head up to and including the blank line
  result = ""
  while true:
    let line = await client.recvLine()
    if line.len == 0 or line == "\r\n":
      break
    result.add(line & "\n")

proc recvAll*(sock: AsyncSocket): Future[string] {.async.} =
  result = ""
  while true:
    let chunk = await sock.recv(4096)
    if chunk.len == 0:
      break
    result.add(chunk)

proc finishWrite*(sock: AsyncSocket) =
  discard shutdown(sock.getFd, shutWrite)

proc closedPort*(): Port =
  let listener = listenLocal()
  result = listener.localPort
  listener.close()

proc startServer*(kind = skAuto): ProxyServer =
  result = server(Port(0), kind = kind)
  result.listen()
  asyncCheck result.serve()

proc proxyFor*(srv: ProxyServer, scheme = "socks5", auth = ""): Proxy =
  parseProxy(scheme & "://" & auth & "127.0.0.1:" & $srv.port.int)

proc proxyFor*(listener: AsyncSocket, scheme = "socks5", auth = ""): Proxy =
  parseProxy(scheme & "://" & auth & "127.0.0.1:" & $listener.localPort.int)
